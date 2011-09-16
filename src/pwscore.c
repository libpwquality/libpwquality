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

#include "pwquality.h"

int
usage(const char *progname) {
        fprintf(stderr, _("Usage: %s\n"), progname);
        fprintf(stderr, _("       The command reads the password to be scored from the standard input.\n"));
}

static const char *
make_error_message(int rv, const char *crack_msg)
{
        static char buf[200];

        switch(rv) {
        case PWQ_ERROR_MEM_ALLOC:
                return _("Memory allocation error");
        case PWQ_ERROR_SAME_PASSWORD:
                return _("The password is the same as the old one");
        case PWQ_ERROR_PALINDROME:
                return _("The password is a palindrome");
        case PWQ_ERROR_CASE_CHANGES_ONLY:
                return _("The password differs with case changes only");
        case PWQ_ERROR_TOO_SIMILAR:
                return _("The password is too similar to the old one");
        case PWQ_ERROR_MIN_DIGITS:
                return _("The password contains too few digits");
        case PWQ_ERROR_MIN_UPPERS:
                return _("The password contains too few uppercase letters");
        case PWQ_ERROR_MIN_LOWERS:
                return _("The password contains too few lowercase letters");
        case PWQ_ERROR_MIN_OTHERS:
                return _("The password contains too few non-alphanumeric characters");
        case PWQ_ERROR_MIN_LENGTH:
                return _("The password is too short");
        case PWQ_ERROR_ROTATED:
                return _("The password is just rotated old one");
        case PWQ_ERROR_MIN_CLASSES:
                return _("The password does not contain enough character classes");
        case PWQ_ERROR_MAX_CONSECUTIVE:
                return _("The password contains too many same characters consecutively");
        case PWQ_ERROR_EMPTY_PASSWORD:
                return _("No password supplied");
        case PWQ_ERROR_CRACKLIB_CHECK:
                snprintf(buf, sizeof(buf), _("The password fails the dictionary check - %s"), crack_msg);
                return buf;
        default:
                return _("Unknown error");
        }
}


/* score a password */
int
main(int argc, char *argv[])
{
        pwquality_settings_t *pwq;
        int rv;
        const char *crack_msg;
        char buf[1024];
        size_t len;

        if (argc != 1) {
                usage(argv[0]);
                exit(3);
        }

        if (fgets(buf, sizeof(buf), stdin) == NULL || (len = strlen(buf)) == 0) {
                fprintf(stderr, "Error: Could not obtain the password to be scored\n");
                exit(4);
        }
        if (buf[len - 1] == '\n')
                buf[len - 1] = '\0';

        pwq = pwquality_default_settings();
        if (pwq == NULL) {
                fprintf(stderr, _("Error: %s\n"), make_error_message(PWQ_ERROR_MEM_ALLOC, NULL));
                exit(2);
        }

        pwquality_read_config(pwq, NULL);

        rv = pwquality_check(pwq, buf, NULL, &crack_msg);

        if (rv < 0) {
                fprintf(stderr, _("Password quality check failed: %s\n"),
                        make_error_message(rv, crack_msg));
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
