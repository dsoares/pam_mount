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

EXTRA_DIST = README_DEBIAN autogen.sh

SUBDIRS = src include dry config scripts

if FLYN
# For local development use only.
# ============================= dist-hook ===================================== 
dist-hook:
	make dry

# ============================= rpm ============================================
rpm: dry dist
	$(BUILD_RPM)

# ============================= check ==========================================
check: rpm
	$(CHECK)

# ============================= publish ========================================
publish: rpm
	$(PUBLISH)
endif
