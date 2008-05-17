
Name:           pam_mount
Version:        0.35
Release:        0
Group:          System/Libraries
Summary:        A PAM module that can mount volumes for a user session
License:        LGPL
URL:            http://pam-mount.sf.net/

Source:         http://heanet.dl.sf.net/sourceforge/pam-mount/%name-%version.tar.bz2
BuildRequires:  libtool pam-devel pkg-config
BuildRequires:  openssl-devel libxml2-devel libHX-devel >= 1.15
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
Requires(post):	perl(XML::Writer)
BuildRoot:      %_tmppath/%name-%version-build
Prefix:         %_prefix

%description
This module is aimed at environments with central file servers that a
user wishes to mount on login and unmount on logout, such as
(semi-)diskless stations where many users can logon.

The module also supports mounting local filesystems of any kind the
normal mount utility supports, with extra code to make sure certain
volumes are set up properly because often they need more than just a
mount call, such as encrypted volumes. This includes SMB/CIFS, NCP,
davfs2, FUSE, losetup crypto, dm-crypt/cryptsetup and truecrypt4.

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
install -pm0755 scripts/convert_pam_mount_conf.pl "$b/%_sbindir/";

%clean
rm -Rf "%buildroot";

%pre
#
# On upgrade, when pmt.conf exists and pmt.conf.xml does not,
# create pmt.conf.xml with size 0 to signal conversion.
#
f="%_sysconfdir/security/pam_mount.conf";
if [ "$1" -eq 2 -a -e "$f" ]; then
	touch -a "$f.xml";
fi;

%post
#
# pmt.conf.xml always exists now.
#
f="%_sysconfdir/security/pam_mount.conf";
if [ -e "$f" -a ! -s "$f.xml" ]; then
	"%_sbindir/convert_pam_mount_conf.pl" \
		<"$f" >"$f.xml";
	echo -en "Configuration migration from pam_mount.conf to pam_mount.conf.xml ";
	if [ "$?" -eq 0 ]; then
		echo "successful - also please check any ~/.pam_mount.conf files.";
	else
		echo "failed";
	fi;
fi;

%files
%defattr(-,root,root)
%config(noreplace) %_sysconfdir/security/%name.conf.xml
/%_lib/security/%{name}*.so
%_sbindir/pmvarrun
%_bindir/*
%_sbindir/*
/sbin/mount.crypt
/sbin/umount.crypt
%_mandir/*/*
%doc doc/*.txt
%if 0%{?_with_selinux:1}
%policy %_sysconfdir/selinux/strict/src/policy/macros/%{name}_macros.te
%policy %_sysconfdir/selinux/strict/src/policy/file_contexts/misc/%name.fc
%endif
