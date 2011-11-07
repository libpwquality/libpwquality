#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# See the end of the file for Copyright and License Information
#

from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext as _build_ext

class build_ext(_build_ext):
    def genconstants(self, headerfile, outputfile):
        hf = open(headerfile, 'r')
        of = open(outputfile, 'w')
        of.write('/* This file is generated during build time from pwquality.h */\n\n')
        for line in hf:
                if line.startswith('#define PWQ_'):
                        s = line.split()
                        of.write('PyModule_AddIntConstant(module, "%s", %s);\n' % (s[1], s[2]))

    def run(self):
        self.genconstants('../src/pwquality.h', 'constants.c')
        _build_ext.run(self)

pwqmodule = Extension('pwquality',
            sources = ['pwquality.c'],
            include_dirs = ['../src'],
            library_dirs = ['../src/.libs'],
            libraries = ['pwquality'])

setup(
    name = 'pwquality',
    version = '0.9.1',
    description = 'Python bindings for the libpwquality library for password quality checking',
    author = 'Tomáš Mráz',
    author_email = 'tm@t8m.info',
    url = 'http://fedorahosted.org/libpwquality',
    license = 'BSD or GPL+',
    ext_modules = [pwqmodule],
    cmdclass = {'build_ext': build_ext}
)

# Copyright (c) Red Hat, Inc, 2011
# Copyright (c) Tomas Mraz <tm@t8m.info>, 2011
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, and the entire permission notice in its entirety,
#    including the disclaimer of warranties.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote
#    products derived from this software without specific prior
#    written permission.
#
# ALTERNATIVELY, this product may be distributed under the terms of
# the GNU Public License, in which case the provisions of the GPL are
# required INSTEAD OF the above restrictions.  (This clause is
# necessary due to a potential bad interaction between the GPL and
# the restrictions contained in a BSD-style copyright.)
#
# THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
