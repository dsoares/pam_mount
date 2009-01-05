# -*- Makefile -*-

dist_man_MANS = mount.crypt.8 mount.crypt_LUKS.8 mount.crypto_LUKS.8 \
		pam_mount.8 pam_mount.conf.5 pmvarrun.8 pmt-ehd.8 \
		pmt-fd0ssh.1 umount.crypt.8 umount.crypt_LUKS.8 \
		umount.crypto_LUKS.8
dist_noinst_DATA = pam_mount.txt

pam_mount.txt: pam_mount.8
	man -l ${srcdir}/pam_mount.8 | perl -pe 's/.\cH//g' >pam_mount.txt;
