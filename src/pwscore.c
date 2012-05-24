/*
 * pwscore - a simple tool for password scoring
 *
 * See the end of the file for Copyright and License Information
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include <locale.h>

#include "pwquality.h"

void
usage(const char *progname) {
        fprintf(stderr, _("Usage: %s [user]\n"), progname);
        fprintf(stderr, _("       The command reads the password to be scored from the standard input.\n"));
}

/* score a password */
int
main(int argc, char *argv[])
{
        pwquality_settings_t *pwq;
        int rv;
        void *auxerror;
        char buf[1024];
        size_t len;
        char *user = NULL;

        setlocale(LC_ALL, "");
        bindtextdomain("libpwquality", "/usr/share/locale");
        textdomain("libpwquality");

        if (argc > 2) {
                usage(basename(argv[0]));
                exit(3);
        }

        if (argc == 2) {
                user = argv[1];
        }

        if (fgets(buf, sizeof(buf), stdin) == NULL || (len = strlen(buf)) == 0) {
                fprintf(stderr, _("Error: %s\n"), _("Could not obtain the password to be scored"));
                exit(4);
        }
        if (buf[len - 1] == '\n')
                buf[len - 1] = '\0';

        pwq = pwquality_default_settings();
        if (pwq == NULL) {
                fprintf(stderr, _("Error: %s\n"), pwquality_strerror(NULL, 0, PWQ_ERROR_MEM_ALLOC, NULL));
                exit(2);
        }

        if ((rv=pwquality_read_config(pwq, NULL, &auxerror)) != 0) {
                fprintf(stderr, _("Error: %s\n"), pwquality_strerror(NULL, 0, rv, auxerror));
                exit(3);
        }

        rv = pwquality_check(pwq, buf, NULL, user, &auxerror);

        if (rv < 0) {
                fprintf(stderr, _("Password quality check failed:\n %s\n"),
                        pwquality_strerror(NULL, 0, rv, auxerror));
                exit(1);
        }

        printf("%d\n", rv);
        return 0;
}

/*
 * Copyright (c) Red Hat, Inc, 2011
 * Copyright (c) Tomas Mraz <tm@t8m.info>, 2011
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED `AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
