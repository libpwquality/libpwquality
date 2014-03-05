#
# Copyright (c) 2005, 2006, 2007, 2009 Thorsten Kukuk <kukuk@thkukuk.de>
# Copyright (c) 2011 Red Hat, Inc.
# Copyright (c) 2011 Tomas Mraz <tm@t8m.info>
#

CLEANFILES = *~

securelibdir = @SECUREDIR@

secureconfdir = @SCONFIGDIR@

EXTRA_DIST = libpwquality.map pwquality.conf pwquality.pc

include_HEADERS = pwquality.h

noinst_HEADERS = pwqprivate.h

if HAVE_LD_VERSION_SCRIPT
  libpwquality_version_script = -Wl,--version-script=$(srcdir)/libpwquality.map
else
  libpwquality_version_script =
endif

libpwquality_la_LDFLAGS = -no-undefined $(libpwquality_version_script) \
	-version-info @PWQUALITY_LT_CURRENT@:@PWQUALITY_LT_REVISION@:@PWQUALITY_LT_AGE@

libpwquality_la_LIBADD = $(LIBCRACK) $(LIBINTL)

libpwquality_la_SOURCES = generate.c check.c settings.c error.c

if HAVE_PAM
  pam_pwquality_la_LDFLAGS = -no-undefined -avoid-version -module
  pam_pwquality_la_LIBADD = libpwquality.la $(PAM_LIBS) $(LIBINTL)
  pam_pwquality_la_SOURCES = pam_pwquality.c
else
  pam_pwquality_la_LDFLAGS =
  pam_pwquality_la_LIBADD =
  pam_pwquality_la_SOURCES =
endif

pwscore_SOURCES = pwscore.c

pwscore_LDADD = libpwquality.la

pwmake_SOURCES = pwmake.c

pwmake_LDADD = libpwquality.la

lib_LTLIBRARIES = libpwquality.la

if HAVE_PAM
  securelib_LTLIBRARIES = pam_pwquality.la
else
  securelib_LTLIBRARIES =
endif

secureconf_DATA = pwquality.conf

bin_PROGRAMS = pwscore pwmake

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = pwquality.pc
