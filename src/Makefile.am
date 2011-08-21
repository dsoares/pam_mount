# -*- Makefile -*-

AM_CPPFLAGS = -DRUNDIR=\"${rundir}\"
AM_CFLAGS = ${regular_CFLAGS} ${GCC_FVISIBILITY_HIDDEN} \
		${libHX_CFLAGS} ${libcrypto_CFLAGS} ${libcryptsetup_CFLAGS} \
		${libmount_CFLAGS} ${libxml_CFLAGS}

moduledir		= @PAM_MODDIR@
module_LTLIBRARIES	= pam_mount.la
sbin_PROGRAMS		= pmvarrun
if HAVE_LIBCRYPTO
sbin_PROGRAMS		+= pmt-ehd
endif
ssbin_PROGRAMS		= mount.crypt
noinst_PROGRAMS		= autoloop ismnt
noinst_SCRIPTS 		= umount.crypt

noinst_LTLIBRARIES	= libpmt_crypto.la libpmt_loop.la libpmt_mtab.la

#
# libpmt_crypto
#
libpmt_crypto_la_SOURCES = crypto.c
libpmt_crypto_la_LIBADD = libpmt_loop.la ${libcrypto_LIBS} ${libHX_LIBS}
if HAVE_LIBCRYPTSETUP
libpmt_crypto_la_SOURCES += crypto-dmc.c
libpmt_crypto_la_LIBADD += ${libcryptsetup_LIBS}
endif
if HAVE_CGD
libpmt_crypto_la_SOURCES += crypto-cgd.c
endif

#
# libpmt_loop
#
libpmt_loop_la_SOURCES = loop.c loop-linux.c
if HAVE_MDIO
libpmt_loop_la_SOURCES += loop-mdvn.c
endif
if HAVE_VND
libpmt_loop_la_SOURCES += loop-vnd.c
endif

#
# libpmt_mtab
#
libpmt_mtab_la_SOURCES = log.c misc.c mtab.c
libpmt_mtab_la_CFLAGS  = ${AM_CFLAGS}
libpmt_mtab_la_LIBADD  = ${libHX_LIBS}

#
# pam_mount.so
#
pam_mount_la_SOURCES	= mount.c mount-bsd.c \
			  mount-sysv.c pam_mount.c \
			  rdconf1.c rdconf2.c spawn.c
pam_mount_la_CFLAGS	= ${AM_CFLAGS}
pam_mount_la_LIBADD	= -lpam libpmt_mtab.la ${libHX_LIBS} \
			  ${libmount_LIBS} ${libxml_LIBS}
pam_mount_la_LDFLAGS	= -module -avoid-version

#
# test tools
#
autoloop_SOURCES	= autoloop.c
autoloop_LDADD		= libpmt_loop.la ${libHX_LIBS}

ismnt_SOURCES		= ismnt.c
ismnt_LDADD		= libpmt_mtab.la

#
# mount helpers
#
mount_crypt_SOURCES	= mtcrypt.c spawn.c
mount_crypt_LDADD	= libpmt_crypto.la libpmt_mtab.la ${libHX_LIBS}

pmt_ehd_SOURCES		= ehd.c log.c misc.c spawn.c
pmt_ehd_LDADD		= libpmt_crypto.la ${libHX_LIBS}

#
# runtime helpers
#
pmvarrun_SOURCES = pmvarrun.c log.c
pmvarrun_LDADD   = ${libHX_LIBS}

EXTRA_DIST = misc.h mount.h pam_mount.h readconfig.h spawn.h

umount.crypt${EXEEXT}: mount.crypt${EXEEXT}
	-${LN_S} $^ $@;

if !KEEP_LA
install-data-hook:
	rm -f $(DESTDIR)$(moduledir)/pam_mount.la;
endif

#
#	udev/libvolume_id detects LUKS volumes as "crypto_LUKS", while
#	blkid/libblkid detects them as "crypt_LUKS".
#	Talking to the maintainers, crypto_LUKS is what was wanted.
#	Providing symlinks for compat...
#
mtcrypt_symlinks = \
	umount.crypt${EXEEXT} \
	mount.crypto_LUKS${EXEEXT} umount.crypto_LUKS${EXEEXT} \
	mount.crypt_LUKS${EXEEXT} umount.crypt_LUKS${EXEEXT}

install-exec-hook:
	${MKDIR_P} ${DESTDIR}${ssbindir};
	-for i in ${mtcrypt_symlinks}; do \
		${LN_S} -f mount.crypt${EXEEXT} "${DESTDIR}${ssbindir}/$$i"; \
	done;

uninstall-hook:
	-for i in ${mtcrypt_symlinks}; do \
		rm "${DESTDIR}${ssbindir}/$$i"; \
	done;
