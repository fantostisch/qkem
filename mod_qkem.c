#include <http_protocol.h>

#include <apr_optional_hooks.h>
#include <mod_ssl_openssl.h>
#include <openssl/ssl.h>
#include <oqs/oqs.h>

#define DEBUG false
#define MASTER_SECRET_LOG "/tmp/ssl_log"

#define PSK_LENGTH 32
#define IDENTITY_LENGTH 16
#define SHARED_SECRET_LENGTH OQS_KEM_kyber_1024_length_shared_secret

// Copied from https://httpd.apache.org/docs/trunk/developer/modguide.html
static int util_read(request_rec* r, const char** rbuf, apr_off_t* size)
{
    /*~~~~~~~~*/
    int rc = OK;
    /*~~~~~~~~*/

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return (rc);
    }

    if (ap_should_client_block(r)) {

        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
        char argsbuffer[HUGE_STRING_LEN];
        apr_off_t rsize, len_read, rpos = 0;
        apr_off_t length = r->remaining;
        /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

        *rbuf = (const char*)apr_pcalloc(r->pool, (apr_size_t)(length + 1));
        *size = length;
        while ((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
            if ((rpos + len_read) > length) {
                rsize = length - rpos;
            } else {
                rsize = len_read;
            }

            memcpy((char*)*rbuf + rpos, argsbuffer, (size_t)rsize);
            rpos += rsize;
        }
    }
    return (rc);
}

typedef struct psk_st {
    char identity[IDENTITY_LENGTH];
    uint8_t shared_secret[SHARED_SECRET_LENGTH];
} psk;

static int sk_psk_cmp(const psk* const* a, const psk* const* b)
{
    return memcmp((*a)->identity, (*b)->identity, IDENTITY_LENGTH);
}

static CRYPTO_ONCE once_run = CRYPTO_ONCE_STATIC_INIT;

DEFINE_STACK_OF_CONST(psk)

STACK_OF(psk) * psks;
CRYPTO_RWLOCK* psk_lock;

static int qkem_handler(request_rec* r)
{
    // todo: r->header_only
    if (strcmp(r->uri, "/.well-known/qkem") != 0) {
        return DECLINED;
    }

    if (strcmp(r->method, "POST") != 0) {
        return HTTP_METHOD_NOT_ALLOWED;
    }

    apr_off_t size;
    const uint8_t* public_key;
    if (util_read(r, (const char**)&public_key, &size) != OK) {
        return HTTP_BAD_REQUEST;
    }

#define public_key_length OQS_KEM_kyber_1024_length_public_key
    if (size != public_key_length) {
        return HTTP_BAD_REQUEST;
    }

    psk* new_psk = OPENSSL_malloc(sizeof(psk));

#define ciphertext_length OQS_KEM_kyber_1024_length_ciphertext
    uint8_t ciphertext[ciphertext_length];
    OQS_STATUS rc = OQS_KEM_kyber_1024_encaps(ciphertext, new_psk->shared_secret, public_key);
    if (rc != OQS_SUCCESS) {
        return HTTP_BAD_REQUEST;
    }

    OQS_randombytes(new_psk->identity, IDENTITY_LENGTH);

    CRYPTO_THREAD_write_lock(psk_lock);
    sk_psk_push(psks, new_psk);
    CRYPTO_THREAD_unlock(psk_lock);

    r->content_type = "application/octet-stream";
    ap_rwrite(new_psk->identity, IDENTITY_LENGTH, r);
    ap_rwrite(ciphertext, ciphertext_length, r);
    return OK;
}

typedef struct ssl_session_st SSL_SESSION;

#if OPENSSL_VERSION_MAJOR == 1
#define TLS13_MAX_RESUMPTION_PSK_LENGTH 256
#else
#define TLS13_MAX_RESUMPTION_PSK_LENGTH 512
#endif

// Unfortunately, necessary to set verify_result. Breaks ABI compatibility.
struct ssl_session_st {
    int ssl_version;
    size_t master_key_length;
    unsigned char early_secret[EVP_MAX_MD_SIZE];
    unsigned char master_key[TLS13_MAX_RESUMPTION_PSK_LENGTH];
    size_t session_id_length;
    unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
#ifndef OPENSSL_NO_PSK
    char* psk_identity_hint;
    char* psk_identity;
#endif
    int not_resumable;
    X509* peer;
    STACK_OF(X509) * peer_chain;
    long verify_result;
};

const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };

static int SSL_psk_find_session_cb(SSL* ssl,
    const unsigned char* identity,
    size_t identity_len,
    SSL_SESSION** sess)
{
    if (identity_len != IDENTITY_LENGTH) {
        return 0;
    }

    psk* identity_psk = OPENSSL_malloc(sizeof(psk));
    memcpy(identity_psk->identity, identity, IDENTITY_LENGTH);

    CRYPTO_THREAD_write_lock(psk_lock);
    int i = sk_psk_find(psks, identity_psk);
    if (i < 0) {
        CRYPTO_THREAD_unlock(psk_lock);
        return 0;
    }
    const psk* found_psk = sk_psk_value(psks, i);
    CRYPTO_THREAD_unlock(psk_lock);

    const STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl);
    if (ciphers == NULL) {
        return 0;
    }
    const SSL_CIPHER* cipher = SSL_CIPHER_find(ssl, tls13_aes128gcmsha256_id);
    if (cipher == NULL) {
        return 0;
    }

    SSL_SESSION* ssl_session = SSL_SESSION_new();
    if (ssl_session == NULL
        || !SSL_SESSION_set1_master_key(ssl_session, found_psk->shared_secret, PSK_LENGTH)
        || !SSL_SESSION_set_cipher(ssl_session, cipher)
        || !SSL_SESSION_set_protocol_version(ssl_session, SSL_version(ssl))) {
        return 0;
    }
    // SSL_SESSION_new sets verify_result to X509_V_ERR_UNSPECIFIED which causes httpd
    // to abort the connection because it then thinks client authentication failed.
    ssl_session->verify_result = X509_V_OK;
    *sess = ssl_session;
    return 1;
}

static void keylog_cb_func(const SSL* ssl, const char* line)
{
    FILE* f = fopen(MASTER_SECRET_LOG, "a");
    fputs(line, f);
    fputc('\n', f);
    fclose(f);
}

static void once_do_run()
{
    psk_lock = CRYPTO_THREAD_lock_new();
    psks = sk_psk_new(sk_psk_cmp);
}

static int qkem_init_server(server_rec* s, apr_pool_t* p, int is_proxy, SSL_CTX* ctx)
{
    CRYPTO_THREAD_run_once(&once_run, once_do_run);
    if (DEBUG) {
        SSL_CTX_set_keylog_callback(ctx, keylog_cb_func);
    }
    SSL_CTX_set_psk_find_session_callback(ctx, SSL_psk_find_session_cb);
    return 0;
}

static void qkem_register_hooks(apr_pool_t* p)
{
    ap_hook_handler(qkem_handler, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, init_server, qkem_init_server, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA qkem_module = {
    STANDARD20_MODULE_STUFF,
    NULL, /* create per-dir config structures */
    NULL, /* merge  per-dir config structures */
    NULL, /* create per-server config structures */
    NULL, /* merge  per-server config structures */
    NULL, /* table of config file commands */
    qkem_register_hooks /* register hooks */
};
