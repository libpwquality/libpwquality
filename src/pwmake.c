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

#include "pwquality.h"

int
usage(const char *progname) {
        fprintf(stderr, _("Usage: %s <entropy-bits>\n"), progname);
}

static const char *
make_error_message(int rv)
{
        switch(rv) {
        case PWQ_ERROR_MEM_ALLOC:
                return _("Memory allocation error");
        case PWQ_ERROR_RNG:
                return _("Cannot obtain random numbers from the RNG device");
        case PWQ_ERROR_GENERATION_FAILED:
                return _("Password generation failed - required entropy too low for settings");
        default:
                return _("Unknown error");
        }
}

/* score a password */
int
main(int argc, char *argv[])
{
        pwquality_settings_t *pwq;
        char *password;
        int rv;
        int bits;

        if (argc != 2) {
                usage(argv[0]);
                exit(3);
        }

        bits = atoi(argv[1]);

        pwq = pwquality_default_settings();
        if (pwq == NULL) {
                fprintf(stderr, "Error: %s\n", _("Error: Memory allocation error"));
                exit(2);
        }

        pwquality_read_config(pwq, NULL);

        rv = pwquality_generate(pwq, bits, &password);

        if (rv != 0) {
                fprintf(stderr, "Error: %s\n", make_error_message(rv));
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
