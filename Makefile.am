# -*- Makefile -*-

ACLOCAL_AMFLAGS  = -I m4
AUTOMAKE_OPTIONS = foreign subdir-objects
SUBDIRS = config doc src

install-data-hook:
	${MKDIR_P} ${DESTDIR}${localstatedir}/run/pam_mount;

TMPDIR ?= /tmp
tmpdir := $(shell mktemp -d ${TMPDIR}/pam_mount.src.XXXXXX)
packer  = lzip
packext = .tar.lz

.PHONY: tarball
tarball:
	pushd ${top_srcdir} && git archive --prefix=${PACKAGE_NAME}-${PACKAGE_VERSION}/ HEAD | tar -C ${tmpdir} -x && popd;
	pushd ${tmpdir}/${PACKAGE_NAME}-${PACKAGE_VERSION} && ./autogen.sh && popd;
	tar --use=${packer} -C ${tmpdir} -cf ${PACKAGE_NAME}-${PACKAGE_VERSION}${packext} --owner=root --group=root ${PACKAGE_NAME}-${PACKAGE_VERSION}/;
	rm -Rf ${tmpdir};
