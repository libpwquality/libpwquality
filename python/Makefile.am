#
# Copyright (c) 2011 Red Hat, Inc.
# Copyright (c) 2011 Tomas Mraz <tm@t8m.info>
#

pythonincdir = $(includedir)/python@PYTHONREV@
pythonsitedir = @PYTHONSITEDIR@

CLEANFILES = *~ constants.c pwquality.so

EXTRA_DIST = pwquality.c setup.py

pythonsite_SCRIPTS = pwquality.so

pwquality.so: ../src/pwquality.h pwquality.c setup.py
	python setup.py build --build-lib=.
