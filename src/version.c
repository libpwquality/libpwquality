/*
 * version.c
 *
 *  Created on: Fri Oct 12, 2018
 *      Author: oc
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ModuleVersionInfo.h"
MODULE_NAME_AUTOTOOLS;
MODULE_AUTHOR_AUTOTOOLS;
MODULE_VERSION_AUTOTOOLS;
MODULE_FILE_VERSION(0.0.0.1);
MODULE_DESCRIPTION(PAM module Password Quality with user profile management);
MODULE_COMMENT(Beta version);
MODULE_COPYRIGHT(GPL);
MODULE_SCM_LABEL_AUTOTOOLS;

// (readelf -l <DSO> to check)
#if defined(__amd64__)
const char elf_interpreter[] __attribute__((section(".interp"))) = "/lib64/ld-linux-x86-64.so.2";
#elif defined(__i386__)
const char elf_interpreter[] __attribute__((section(".interp"))) = "/lib/ld-linux.so.2";
#elif defined (__aarch64__)
const char elf_interpreter[] __attribute__((section(".interp"))) = "/lib/ld-linux-aarch64.so.1";
#else
#error "unsupported architecture"
#endif

void displayVersionInfo(void)  __attribute__ ((noreturn));

#define DISPLAY(t,x) \
{ \
	const char *value = strchr(x,'=')+1; \
	if (value) printf(t " %s\n",value); \
}

void displayVersionInfo(void)
{
    DISPLAY("Library :",__module_name);
    DISPLAY("Author:",__module_author);
    DISPLAY("File version:",__module_file_modinfo);
    DISPLAY("CSC Version:",__module_modinfo);
    DISPLAY("Description:",__module_description);
    DISPLAY("Comment:",__module_comment);
    DISPLAY("(C) Copyright:",__module_copyright);

    _exit(EXIT_SUCCESS);
}
/* _LDFLAGS = -Wl,-e,displayVersionInfo */

