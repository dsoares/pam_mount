
%define wname pam-mount
Name:     pam_mount
Version:  0.12.0
Release:  0
Group:    System/Libraries
URL:      http://pam-mount.sf.net/
Summary:  A PAM module that can mount volumes for a user session

Source:   http://heanet.dl.sf.net/sourceforge/%wname/%name-%version.tbz2
License:  LGPL2
Requires: pam
BuildRequires: glib2-devel pam-devel openssl-devel zlib-devel
BuildRoot: %_tmppath/%name-%version-build

%description
This module is aimed at environments with SMB (Samba or Windows NT) 
or NCP (Netware or Mars-NWE) servers that Unix users wish to access 
transparently. It facilitates access to private volumes of these types 
well. The module also supports mounting home directories using 
loopback encrypted filesystems. The module was originally written for 
use on the GNU/Linux operating system but has since been modified to 
work on several flavors of BSD.

 - Every user can access his own volumes

 - The user needs to type the password just once (at login)

 - The mounting process is transparent to the users

 - There is no need to keep the login passwords in any additional file

 - The volumes are unmounted upon logout, so it saves system resources, 
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
CFLAGS="$RPM_OPT_FLAGS" CXXFLAGS="$RPM_OPT_FLAGS" \
  ./configure --prefix=%_prefix --sysconfdir=%_sysconfdir --libdir=/%_lib \
  --localstatedir=%_localstatedir --infodir=%_infodir --mandir=%_mandir \
  --disable-debug;
make;

%install
b="$RPM_BUILD_ROOT";
[ "$b" != "/" -a -d "$b" ] && rm -Rf "$b";
make -i install DESTDIR="$b";
mkdir -p "$b/%_sysconfdir/security";
install -m0644 config/pam_mount.conf "$b/%_sysconfdir/security/";
find "$b" -type f -perm +111 -print0 | xargs -0 strip -s &>/dev/null || :;

#mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/security
#mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/selinux/strict/src/policy/macros
#mkdir -p ${RPM_BUILD_ROOT}/%{_sysconfdir}/selinux/strict/src/policy/file_contexts/misc
#install --owner=root --group=root --mode=0644 config/pam_mount.conf ${RPM_BUILD_ROOT}/%{_sysconfdir}/security
#install --owner=root --group=root --mode=0644 config/pam_mount_macros.te ${RPM_BUILD_ROOT}/%{_sysconfdir}/selinux/strict/src/policy/macros
#install --owner=root --group=root --mode=0644 config/pam_mount.fc ${RPM_BUILD_ROOT}/%{_sysconfdir}/selinux/strict/src/policy/file_contexts/misc
#rm -f ${RPM_BUILD_ROOT}/%{_lib}/security/pam_mount.a
#rm -f ${RPM_BUILD_ROOT}/%{_lib}/security/pam_mount.la

%clean
b="$RPM_BUILD_ROOT";
[ "$b" != "/" -a -d "$b" ] && rm -Rf "$b";
rm -Rf "$b";

%files
%defattr(-,root,root)
%config(noreplace) %_sysconfdir/security/%name.conf
/%_lib/security/%name.so
%_sbindir/pmvarrun
%_bindir/mkehd
%_bindir/autoehd
%_bindir/passwdehd
%_bindir/mount_ehd
%_bindir/mount.crypt
%_bindir/umount.crypt
%_mandir/man8/*
#%policy %_sysconfdir/selinux/strict/src/policy/macros/%{name}_macros.te
#%policy %_sysconfdir/selinux/strict/src/policy/file_contexts/misc/%name.fc
%doc AUTHORS COPYING ChangeLog INSTALL NEWS README FAQ TODO
