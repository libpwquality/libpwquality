#!/bin/sh
set -x
aclocal -I m4
autoheader
automake -a
autoconf
