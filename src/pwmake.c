/*
 * pwmake - a simple tool for password generation
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
        fprintf(stderr, _("Usage: %s <entropy-bits>\n"), progname);
}


/* score a password */
int
main(int argc, char *argv[])
{
        pwquality_settings_t *pwq;
        char *password;
        int rv;
        int bits;
        void *auxerror;

        setlocale(LC_ALL, "");
        bindtextdomain("libpwquality", "/usr/share/locale");
        textdomain("libpwquality");

        if (argc != 2) {
                usage(basename(argv[0]));
                exit(3);
        }

        bits = atoi(argv[1]);

        pwq = pwquality_default_settings();
        if (pwq == NULL) {
                fprintf(stderr, "Error: %s\n", pwquality_strerror(NULL, 0, PWQ_ERROR_MEM_ALLOC, NULL));
                exit(2);
        }

        if ((rv = pwquality_read_config(pwq, NULL, &auxerror)) != 0) {
                fprintf(stderr, "Error: %s\n", pwquality_strerror(NULL, 0, rv, auxerror));
                pwquality_free_settings(pwq);
                exit(3);
        }

        rv = pwquality_generate(pwq, bits, &password);
        pwquality_free_settings(pwq);

        if (rv != 0) {
                fprintf(stderr, "Error: %s\n", pwquality_strerror(NULL, 0, rv, NULL));
                exit(1);
        }

        printf("%s\n", password);
        free(password);
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
 * the GNU General Public License version 2 or later, in which case the
 * provisions of the GPL are required INSTEAD OF the above restrictions.
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
