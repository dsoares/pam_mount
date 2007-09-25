
Name:           pam_mount
Version:        0.26
Release:        0
Group:          System/Libraries
Summary:        A PAM module that can mount volumes for a user session
License:        LGPL
URL:            http://pam-mount.sf.net/

Source:         http://heanet.dl.sf.net/sourceforge/pam-mount/%name-%version.tar.bz2
Suggests:	lsof
BuildRequires:  libtool linux-kernel-headers pam-devel
BuildRequires:  openssl-devel libxml2-devel libHX-devel >= 1.10
BuildRoot:      %_tmppath/%name-%version-build
Prefix:         %_prefix

%description
pam_mount automatically mounts directories when the user logs in,
using the password just entered.

pam_mount supports SMB, NCP, and any type of filesystem that can
be mounted using the standard mount command.

## Remove the debug_package line to compile under FedoraCore
%debug_package
%prep
%setup

%build
%configure --disable-static --with-ssbindir=/sbin --with-slibdir=/%_lib
make %{?jobs:-j%jobs};

%install
b="%buildroot";
rm -Rf "$b";
make -i install DESTDIR="$b";
mkdir -p "$b/%_sysconfdir/security";
install -m0644 config/pam_mount.conf.xml "$b/%_sysconfdir/security/";

%clean
rm -Rf "%buildroot";

%files
%defattr(-,root,root)
%config(noreplace) %_sysconfdir/security/%name.conf.xml
/%_lib/security/%{name}*.so
%_sbindir/pmvarrun
%_bindir/mkehd
%_bindir/autoehd
%_bindir/passwdehd
%_bindir/mount_ehd
/sbin/mount.crypt
/sbin/umount.crypt
%_mandir/*/*
%doc doc/*.txt scripts/convert_pam_mount_conf.pl

%changelog -n pam_mount
