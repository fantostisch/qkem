mod_qkem.la: mod_qkem.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_qkem.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_qkem.la
