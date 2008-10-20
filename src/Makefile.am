# -*- Makefile -*-

AM_CFLAGS = ${regular_CFLAGS} ${GCC_FVISIBILITY_HIDDEN} \
		${libHX_CFLAGS} ${libxml_CFLAGS}

moduledir		= @PAM_MODDIR@
module_LTLIBRARIES	= pam_mount.la
bin_PROGRAMS		= pmt-fd0ssh pmt-ofl
sbin_PROGRAMS		= pmt-ehd pmvarrun
ssbin_PROGRAMS		= mount.crypt mount.encfs13
noinst_PROGRAMS		= umount.crypt

pam_mount_la_SOURCES	= loop.c misc.c ofl-lib.c pam_mount.c \
			  rdconf1.c rdconf2.c mount.c spawn.c
pam_mount_la_LIBADD	= -lpam ${libHX_LIBS} ${libcrypto_LIBS} \
			  ${libssl_LIBS} ${libxml_LIBS}
pam_mount_la_LDFLAGS	= -module -avoid-version

mount_crypt_SOURCES	= mtcrypt.c nlt-loop.c nlt-misc.c nlt-spawn.c
mount_crypt_LDADD	= ${libHX_LIBS} ${libcrypto_LIBS} ${libssl_LIBS}

mount_encfs13_SOURCES	= mtencfs13.c
mount_encfs13_LDADD	= ${libHX_LIBS}

pmt_ehd_SOURCES		= ehd.c nlt-loop.c nlt-misc.c nlt-spawn.c
pmt_ehd_LDADD		= ${libHX_LIBS} ${libcrypto_LIBS} ${libssl_LIBS}

pmt_fd0ssh_SOURCES	= fd0ssh.c

pmt_ofl_SOURCES		= ofl.c nlt-ofl-lib.c
pmt_ofl_LDADD		= ${libHX_LIBS}

pmvarrun_SOURCES = pmvarrun.c nlt-misc.c
pmvarrun_LDADD   = ${libHX_LIBS}

umount.crypt: mount.crypt
	-${LN_S} $^ $@;

install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/pam_mount.la;

install-exec-hook:
	mkdir -p "${DESTDIR}${ssbindir}";
	-for i in umount.crypt mount.crypt_LUKS umount.crypt_LUKS; do ${LN_S} -f mount.crypt "${DESTDIR}${ssbindir}/$i"; done;
