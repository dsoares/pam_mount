# -*- Makefile -*-

AM_CPPFLAGS = -DLOCALSTATEDIR=\"${varrundir}\"
AM_CFLAGS = ${regular_CFLAGS} ${GCC_FVISIBILITY_HIDDEN} \
		${libHX_CFLAGS} ${libcrypto_CFLAGS} ${libcryptsetup_CFLAGS} \
		${libxml_CFLAGS}

varrundir		= ${localstatedir}/run

moduledir		= @PAM_MODDIR@
module_LTLIBRARIES	= pam_mount.la
sbin_PROGRAMS		= pmvarrun
if HAVE_LIBCRYPTO
sbin_PROGRAMS		+= pmt-ehd
endif
ssbin_PROGRAMS		= mount.crypt mount.encfs13
noinst_PROGRAMS		= autoloop ismnt
noinst_SCRIPTS 		= umount.crypt

crypto_sources		= crypto.c ${loop_sources}
if HAVE_LIBCRYPTSETUP
crypto_sources		+= crypto-dmc.c
endif
if HAVE_CGD
crypto_sources		+= crypto-cgd.c
endif
crypto_libs		= ${libcrypto_LIBS} ${libcryptsetup_LIBS}
loop_sources		= loop.c loop-linux.c
if HAVE_MDIO
loop_sources		+= loop-mdvn.c
endif
if HAVE_VND
loop_sources		+= loop-vnd.c
endif
mtab_sources		= log.c misc.c mtab.c

pam_mount_la_SOURCES	= ${mtab_sources} mount.c mount-bsd.c \
			  mount-sysv.c pam_mount.c \
			  rdconf1.c rdconf2.c spawn.c
# Separate compilation required
pam_mount_la_CFLAGS	= ${AM_CFLAGS}
pam_mount_la_LIBADD	= -lpam ${libHX_LIBS} ${crypto_libs} \
			  ${libxml_LIBS}
pam_mount_la_LDFLAGS	= -module -avoid-version

autoloop_SOURCES	= autoloop.c ${loop_sources} log.c misc.c spawn.c
autoloop_LDADD		= ${libHX_LIBS}

ismnt_SOURCES		= ismnt.c ${mtab_sources}
ismnt_LDADD		= ${libHX_LIBS}

mount_crypt_SOURCES	= mtcrypt.c spawn.c \
			  ${crypto_sources} ${mtab_sources}
mount_crypt_LDADD	= ${libHX_LIBS} ${crypto_libs}

mount_encfs13_SOURCES	= mtencfs13.c
mount_encfs13_LDADD	= ${libHX_LIBS}

pmt_ehd_SOURCES		= ehd.c log.c misc.c spawn.c ${crypto_sources}
pmt_ehd_LDADD		= ${libHX_LIBS} ${crypto_libs}

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

