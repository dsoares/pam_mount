# -*- Makefile -*-

securitydir   = ${sysconfdir}/security
security_DATA = pam_mount.conf.xml
if SELINUX
selinux_fcdir   = ${sysconfdir}/selinux/strict/src/policy/file_contexts/misc
selinux_tedir   = ${sysconfdir}/selinux/strict/src/policy/macros
selinux_fc_DATA = pam_mount.fc
selinux_te_DATA = pam_mount_macros.te
endif
