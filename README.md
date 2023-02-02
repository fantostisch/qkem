# Apache qkem module

Apache module to protect against eavesdroppers who will have a quantum computer in the future.

## Todo list

Todo list / Reasons not to use this in production yet:

* Could break on openssl update because of usage of non-public API.
* No cryptographic agility: can not easily switch underlying cryptography without updating all clients and servers at once.
* Not tested with TLS 1.2.
* PSK are not automatically removed, which is a memory leak.

## Development

### Building dependencies

Get submodules:

    git submodule update --init --recursive

Then [build liboqs](lib/liboqs/README.md).

Then install development dependencies:

    sudo apt install apache2-dev apache2-ssl-dev libssl-dev

## Installation

To use this module, compile it and install it into Apache's modules directory by running:

    make
    sudo make install

Then add the following to your Apache's configuration:

    #   apache2.conf (or use mods-available/qkem.load)
    LoadModule qkem_module modules/mod_qkem.so
    # On Debian use:
    # LoadModule qkem_module /usr/lib/apache2/modules/mod_qkem.so
    <Location /.well-known/qkem>
    SetHandler qkem
    </Location>

Then restart Apache:

    sudo apachectl restart

## Testing examples

    wget --post-file ../kyber1024pubkey https://DOMAIN/.well-known/qkem

    openssl s_client -psk_identity=Client_identity -psk 0101010101010101010101010101010101010101010101010101010101010101 -connect localhost:443

## Usage

To use this module, do the following in a client connecting to the server:

1. Generate a Kyber 1024 public key and POST this key over TLS to `/.well-known/qkem`.
2. Use the first 16 bytes of the response as the identity for TLS-PSK. The remaining bytes are the ciphertext of the Kyber key exchange.
3. Decrypt the ciphertext using your Kyber private key.
4. Use the decrypted shared secret as the preshared key for TLS-PSK.
5. Create a new TLS connection to the server, this time using TLS-PSK (possibly combined with ECDH).
