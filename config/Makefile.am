# -*- Makefile -*-

securitydir   = ${sysconfdir}/security
dist_security_DATA = pam_mount.conf.xml
if SELINUX
selinux_fcdir   = ${sysconfdir}/selinux/strict/src/policy/file_contexts/misc
selinux_tedir   = ${sysconfdir}/selinux/strict/src/policy/macros
dist_selinux_fc_DATA = pam_mount.fc
dist_selinux_te_DATA = pam_mount_macros.te
endif
