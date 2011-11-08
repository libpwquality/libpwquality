#!/bin/sh
set -x
autopoint --force
libtoolize --force --copy
aclocal -I m4
autoheader
automake -a
autoconf
