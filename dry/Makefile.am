#   FILE: Makefile.am -- 
# AUTHOR: W. Michael Petullo <mike@flyn.org>
#   DATE: 03 August 2002
# 
# Copyright (C) 2002 W. Michael Petullo <mike@flyn.org>
# All rights reserved.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


if FLYN
# For local development use only.
include /etc/fctk/config.mk
endif

AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = pam_mount.spec

if FLYN
# For local development use only.
$(PACKAGE).spec: $(PACKAGE).spec.new
	new -f -t $(PACKAGE).spec.new $(PACKAGE).spec

README.txt: README.xml overview_pam_mount.xml nasty-details_pam_mount.xml

one_liner_wrapper.txt: one_liner_wrapper.xml one_liner_pam_mount.xml

overview_wrapper.txt: overview_wrapper.xml overview_pam_mount.xml

# ============================= all =========================================== 
all: $(PACKAGE).spec README.txt overview_wrapper.txt one_liner_wrapper.txt
	cp README.txt ../README
	mv overview_wrapper.txt overview_pam_mount.txt

endif
