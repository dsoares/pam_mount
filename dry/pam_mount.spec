#   FILE: pam_mount.spec.new.in -
# AUTHOR: W. Michael Petullo (mike@flyn.org)
#   DATE: 03 August 2002
# 
# Copyright (C) 2002 W. Michael Petullo (mike@flyn.org)
# All rights reserved.


%define rel 1
%define prefix /usr

Summary: a PAM module that can mount remote volumes for a user session
Name: pam_mount
Version: 0.5.1
Release: %rel
Copyright: LGPL
Group: System Environment/Base
Source: %name-%{PACKAGE_VERSION}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
Packager: W. Michael Petullo <mike@flyn.org>
Vendor: Flyn Computing
Distribution: Flyn Linux
URL: http://www.flyn.org
Requires: pam

# ============================= description ====================================
%description

     _________________________________________________________

   Table of Contents

   This  module  is  aimed  at  environments  with  SMB (Samba or
   Windows  NT)  or  NCP  (Netware or Mars-NWE) servers that Unix
   users  wish  to access transparently. It facilitates access to
   private  volumes of these types well. The module also supports
   mounting    home    directories   using   loopback   encrypted
   filesystems.

     * Every user can access his own volumes
     * The user needs to type the password just once (at login)
     * The mouting process is transparent to the users
     * There  is  no  need  to  keep  the  login passwords in any
       additional file
     * The  volumes  are  unmount upon logout, so it saves system
       resources,  avoiding  the  need  of  listing  every  every
       possibly  useful  remote  volume  in  /etc/fstab  or in an
       automount/supermount  config  file. This is also necessary
       for securing encrypted filesystems.

   Pam_mount  "understands"  SMB,  NCP,  and  encrypted  loopback
   volumes,  but this can be extended very easily. If someone has
   a particular need for a different filesystem, feel free to ask
   me to include it and / or send me patches.


# ============================= changelog ======================================
%changelog

# ============================= prep ===========================================
%prep

# ============================= setup ==========================================
%setup

# ============================= build ==========================================
%build
CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=/usr
make

# ============================= install ========================================
%install
mkdir -p $RPM_BUILD_ROOT/usr/bin

# NOTE: The following trick only works with a modified header-vars.am.
# Change the line ``DESTDIR ='' in this file to ``DESTDIR =
# ${ENV_DESTDIR}.''
export ENV_DESTDIR=$RPM_BUILD_ROOT
make install

gzip -9 AUTHORS COPYING ChangeLog INSTALL NEWS README

# ============================= clean ==========================================
%clean
rm -rf $RPM_BUILD_ROOT

# ============================= pre ============================================
%pre

# ============================= post ===========================================
%post

# ============================= preun ==========================================
%preun

# ============================= postun =========================================
%postun

# ============================= files ==========================================
%files
%defattr(-, root, root)
%{prefix}/bin/pmhelper
%{prefix}/bin/mkehd
%{prefix}/bin/passwdehd
/lib/security/pam_mount.so
%config(noreplace) /etc/security/pam_mount.conf

# ============================= doc ============================================
%doc AUTHORS.gz COPYING.gz ChangeLog.gz INSTALL.gz NEWS.gz README.gz

# ============================= config =========================================
%config
