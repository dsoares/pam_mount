
Name:           pam_mount
Version:        0.29
Release:        1
Group:          System/Libraries
Summary:        A PAM module that can mount volumes for a user session
License:        LGPL
URL:            http://pam-mount.sf.net/

Source:         http://heanet.dl.sf.net/sourceforge/pam-mount/%name-%version.tar.bz2
BuildRequires:  libtool pam-devel
BuildRequires:  openssl-devel libxml2-devel libHX-devel >= 1.10
%if "%_vendor" == "suse"
BuildRequires:	linux-kernel-headers
# psmisc: /bin/fuser
Recommends:	cifs-mount lsof psmisc
%if %suse_version < 1030
Recommends:	util-linux-crypto
%else
Recommends:	cryptsetup
%endif
%endif
%if "%_vendor" == "redhat"
BuildRequires:	kernel-headers
Requires:	cryptsetup-luks lsof psmisc samba-client
%endif
BuildRoot:      %_tmppath/%name-%version-build
Prefix:         %_prefix

%description
pam_mount automatically mounts directories when the user logs in,
using the password just entered.

pam_mount supports SMB, NCP, and any type of filesystem that can
be mounted using the standard mount command.

%debug_package
%prep
%setup

%build
%configure --with-slibdir=/%_lib %{?_with_selinux:--with-selinux}
make %{?jobs:-j%jobs};

%install
b="%buildroot";
rm -Rf "$b";
make -i install DESTDIR="$b";
mkdir -p "$b/%_sysconfdir/security" "$b/%_sbindir";
install -pm0755 scripts/convert_pam_mount_conf.pl "$b/%_sbindir/";

%clean
rm -Rf "%buildroot";

%post
if [ -e %_sysconfdir/security/pam_mount.conf -a \
    ! -e %_sysconfdir/security/pam_mount.conf.xml ]; then
	%_sbindir/convert_pam_mount_conf.pl \
		<%_sysconfdir/security/pam_mount.conf \
		>%_sysconfdir/security/pam_mount.conf.xml;                 
	echo "Configuration migrated from pam_mount.conf to pam_mount.conf.xml.";
fi;

%files
%defattr(-,root,root)
%config(noreplace) %_sysconfdir/security/%name.conf.xml
/%_lib/security/%{name}*.so
%_sbindir/pmvarrun
%_bindir/mkehd
%_bindir/autoehd
%_bindir/passwdehd
%_bindir/mount_ehd
%_sbindir/*
/sbin/mount.crypt
/sbin/umount.crypt
%_mandir/*/*
%doc doc/*.txt
%if 0%{?_with_selinux:1}
%policy %_sysconfdir/selinux/strict/src/policy/macros/%{name}_macros.te
%policy %_sysconfdir/selinux/strict/src/policy/file_contexts/misc/%name.fc
%endif

%changelog -n pam_mount
