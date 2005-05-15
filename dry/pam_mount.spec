Summary: A PAM module that can mount volumes for a user session
Name: pam_mount
Version: 0.9.24
Release: 1
License: LGPL
Group: System Environment/Base
Source: http://www.flyn.org/projects/%name/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
URL: http://www.flyn.org
Requires: pam
BuildRequires: glib2-devel pam-devel openssl-devel zlib-devel

%description
This module is aimed at environments with SMB (Samba or Windows NT) 
or NCP (Netware or Mars-NWE) servers that Unix users wish to access 
transparently. It facilitates access to private volumes of these types 
well. The module also supports mounting home directories using 
loopback encrypted filesystems. The module was originally written for 
use on the GNU/Linux operating system but has since been modified to 
work on several flavors of BSD.

 o Every user can access his own volumes

 o The user needs to type the password just once (at login)

 o The mounting process is transparent to the users

 o There is no need to keep the login passwords in any additional file

 o The volumes are unmounted upon logout, so it saves system resources, 
 avoiding the need of listing every every possibly useful remote 
 volume in /etc/fstab or in an automount/supermount config file. This 
 is also necessary for securing encrypted filesystems.

Pam_mount "understands" SMB, NCP, and any type of filesystem that can 
be mounted using the standard mount command. If someone has a 
particular need for a different filesystem, feel free to ask me to 
include it and send me patches.

If you intend to use pam_mount to protect volumes on your computer 
using an encrypted filesystem system, please know that there are many 
other issues you need to consider in order to protect your data. 
For example, you probably want to disable or encrypt your swap 
partition (the cryptoswap can help you do this). Don't assume a 
system is secure without carefully considering potential threats.



%prep


%setup


%build
%configure --libdir=/%{_lib}
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall libdir=/%{_lib}
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/security
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/selinux/strict/src/policy/macros
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/selinux/strict/src/policy/file_contexts/misc
install --owner=root --group=root --mode=0644 config/pam_mount.conf ${RPM_BUILD_ROOT}/%{_sysconfdir}/security
install --owner=root --group=root --mode=0644 config/pam_mount_macros.te ${RPM_BUILD_ROOT}/%{_sysconfdir}/selinux/strict/src/policy/macros
install --owner=root --group=root --mode=0644 config/pam_mount.fc ${RPM_BUILD_ROOT}/%{_sysconfdir}/selinux/strict/src/policy/file_contexts/misc
rm -f ${RPM_BUILD_ROOT}/%{_lib}/security/pam_mount.a
rm -f ${RPM_BUILD_ROOT}/%{_lib}/security/pam_mount.la


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-, root, root)
/%{_lib}/security/pam_mount.so
/%{_lib}/security/pam_mount_auth.so
/%{_lib}/security/pam_mount_session.so
%{_sbindir}/pmvarrun
%{_bindir}/mkehd
%{_bindir}/autoehd
%{_bindir}/passwdehd
%{_bindir}/mount_ehd
%{_bindir}/mount.crypt
%{_bindir}/umount.crypt
%{_mandir}/man8/*
%config(noreplace) %{_sysconfdir}/security/pam_mount.conf
%policy %{_sysconfdir}/selinux/strict/src/policy/macros/pam_mount_macros.te
%policy %{_sysconfdir}/selinux/strict/src/policy/file_contexts/misc/pam_mount.fc


%doc	AUTHORS COPYING ChangeLog INSTALL NEWS README FAQ


%changelog
* Sat May 14 2005 W. Michael Petullo <mike[@]flyn.org> - 0.9.24-1
   - Updated to pam_mount 0.9.24.

* Wed May 04 2005 W. Michael Petullo <mike[@]flyn.org> - 0.9.23-1
   - Updated to pam_mount 0.9.23.

   - Remove fdr from version.

   - Get rid of rel variable.

   - %{PACKAGE_VERSION} to %{name}-%{version}.

* Thu Feb 10 2005 W. Michael Petullo <mike[@]flyn.org> - 0.9.22-0.fdr.1
   - Updated to pam_mount 0.9.22.

   - Should now build properly on x86-64.

* Sun Dec 12 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.21-0.fdr.1
   - Updated to pam_mount 0.9.21.

* Fri Jul 23 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.20-0.fdr.1
   - Updated to pam_mount 0.9.20.

* Sun Jun 27 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.19-0.fdr.1
   - Updated to pam_mount 0.9.19.

   - Moved policy sources to /etc/selinux.

* Sun Apr 25 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.18-0.fdr.1
   - Updated to pam_mount 0.9.18.

   - Added mount.crypt and umount/crypt.

   - Added pmvarrun.

* Wed Apr 21 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.17-0.fdr.1
   - Updated to pam_mount 0.9.17.

   - Added pam_mount_macros.te.

* Tue Mar 23 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.16-0.fdr.1
   - Updated to pam_mount 0.9.16.

   - Ensure pam_mount.conf etc. has safe permissions (install vs. cp).

   - Don't compress documentation files.

   - Don't set distribution in .spec.

   - Remove uneeded prefix definition.

   - Fix buildroot.

* Wed Mar 10 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.15-0.fdr.1
   - Updated to pam_mount 0.9.15.

   - Added zlib-devel to BuildRequires.

* Tue Feb 10 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.14-0.fdr.1
   - Updated to pam_mount 0.9.14.

   - Added pam_mount_auth.so and pam_mount_session.so to package.

* Sat Jan 25 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.13-0.fdr.1
   - Updated to pam_mount 0.9.13.

* Sat Jan 24 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.12-0.fdr.2
   - RPM specification work.

* Fri Jan 23 2004 W. Michael Petullo <mike[@]flyn.org> - 0.9.12-0.fdr.1
   - Updated to pam_mount 0.9.12.




