#!/bin/sh

aclocal
autoconf
autoheader
libtoolize --force
automake -a

exit 0
