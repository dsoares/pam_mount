
Name:		pam_mount
Version:	0.48
Release:	0
Group:		System/Libraries
Summary:	A PAM module that can mount volumes for a user session
License:	LGPL
URL:		http://pam-mount.sf.net/

Source:		http://downloads.sf.net/pam-mount/%name-%version.tar.lzma
BuildRequires:	libtool lzma pam-devel pkg-config
BuildRequires:	openssl-devel >= 0.9.6, libxml2-devel >= 2.6
BuildRequires:	libHX-devel >= 1.25
%if "%_vendor" == "suse"
BuildRequires:	linux-kernel-headers >= 2.6
Recommends:	cifs-mount xfsprogs
%if %suse_version < 1030
Recommends:	util-linux-crypto
%else
Recommends:	cryptsetup
%endif
%endif
%if "%_vendor" == "redhat"
BuildRequires:	kernel-headers
Requires:	cryptsetup-luks samba-client xfsprogs
%endif
Requires(post):	perl(XML::Writer)
BuildRoot:	%_tmppath/%name-%version-build
Prefix:		%_prefix

%description
This module is aimed at environments with central file servers that a
user wishes to mount on login and unmount on logout, such as
(semi-)diskless stations where many users can logon.

The module also supports mounting local filesystems of any kind the
normal mount utility supports, with extra code to make sure certain
volumes are set up properly because often they need more than just a
mount call, such as encrypted volumes. This includes SMB/CIFS, FUSE,
dm-crypt and LUKS.

%if "%_vendor" != "redhat"
%debug_package
%endif

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

%clean
rm -Rf "%buildroot";

%files
%defattr(-,root,root)
%config(noreplace) %_sysconfdir/security/%name.conf.xml
/%_lib/security/%{name}*.so
%_sbindir/pmvarrun
%_bindir/*
%_sbindir/*
/sbin/*
%_mandir/*/*
%doc doc/*.txt
%if 0%{?_with_selinux:1}
%policy %_sysconfdir/selinux/strict/src/policy/macros/%{name}_macros.te
%policy %_sysconfdir/selinux/strict/src/policy/file_contexts/misc/%name.fc
%endif
