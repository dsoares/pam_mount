#!/bin/sh
# Generate the Makefiles and configure files
if !( aclocal --version ) </dev/null > /dev/null 2>&1; then
    echo "aclocal not found -- aborting"
    exit
fi

if !( autoheader --version ) </dev/null > /dev/null 2>&1; then
    echo "autoheader not found -- aborting"
    exit
fi

if !( automake --version ) </dev/null > /dev/null 2>&1; then
    echo "automake not found -- aborting"
    exit
fi

if !( autoconf --version ) </dev/null > /dev/null 2>&1; then
    echo "autoconf not found -- aborting"
    exit
fi
echo "Building macros" && aclocal && \
echo "Building config header template" && autoheader && \
echo "Building Makefiles" && automake -a && \
echo "Building configure" && autoconf
if [ $? != 0 ]; then
    echo "Autogeneration failed (exit code $?)"
else
    echo 'run "./configure; make"'
fi

