%define rel 0.fdr.1
%define prefix /usr

Summary: A PAM module that can mount volumes for a user session
Name: pam_mount
Version: 0.9.15
Release: %rel
License: LGPL
Group: System Environment/Base
Source: http://www.flyn.org/projects/%name/%name-%{PACKAGE_VERSION}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Distribution: Flyn Linux
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
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall
gzip -9 AUTHORS COPYING ChangeLog INSTALL NEWS README FAQ
mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/security
cp config/pam_mount.conf ${RPM_BUILD_ROOT}/%{_sysconfdir}/security
rm -f ${RPM_BUILD_ROOT}/%{_lib}/security/pam_mount.a
rm -f ${RPM_BUILD_ROOT}/%{_lib}/security/pam_mount.la


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-, root, root)
/%{_lib}/security/pam_mount.so
/%{_lib}/security/pam_mount_auth.so
/%{_lib}/security/pam_mount_session.so
%{_bindir}/mkehd
%{_bindir}/autoehd
%{_bindir}/passwdehd
%{_bindir}/mount_ehd
%{_mandir}/man8/*
%config(noreplace) %{_sysconfdir}/security/pam_mount.conf


%doc	AUTHORS.gz COPYING.gz ChangeLog.gz INSTALL.gz NEWS.gz README.gz FAQ.gz


%changelog
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




