%define rel 0.fdr.1
%define prefix /usr

Summary: A PAM module that can mount volumes for a user session
Name: pam_mount
Version: 0.9.11
Release: %rel
License: LGPL
Group: System Environment/Base
Source: %name-%{PACKAGE_VERSION}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Packager: W. Michael Petullo <mike@flyn.org>
Distribution: Flyn Linux
URL: http://www.flyn.org
Requires: pam
BuildRequires: glib2-devel

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



%changelog


%prep


%setup


%build
%configure
make %{?_smp_mflags}

%install
%makeinstall
gzip -9 AUTHORS COPYING ChangeLog INSTALL NEWS README FAQ
mkdir -p ${RPM_BUILD_ROOT}/etc/security
cp config/pam_mount.conf ${RPM_BUILD_ROOT}/etc/security
rm -f ${RPM_BUILD_ROOT}/lib/security/pam_mount.a
rm -f ${RPM_BUILD_ROOT}/lib/security/pam_mount.la


%clean
rm -rf $RPM_BUILD_ROOT


%pre

%post

%preun

%postun

%files
%defattr(-, root, root)
/lib/security/pam_mount.so
%{prefix}/bin/mkehd
%{prefix}/bin/autoehd
%{prefix}/bin/passwdehd
%{prefix}/bin/mount_ehd
%doc %{_mandir}
%config(noreplace) %{_sysconfdir}/security/pam_mount.conf


%doc	AUTHORS.gz COPYING.gz ChangeLog.gz INSTALL.gz NEWS.gz README.gz FAQ.gz


