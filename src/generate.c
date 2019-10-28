/*
 * libpwquality main API code for password generation
 *
 * See the end of the file for Copyright and License Information
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <crack.h>
#include <errno.h>

#include "pwqprivate.h"
#include "pwquality.h"

#ifndef PATH_DEV_URANDOM
#define PATH_DEV_URANDOM "/dev/urandom"
#endif

static char vowels[] = { 'a', '4', 'A', 'e', 'E', '3', 'i', 'I', 'o', 'O',
        '0', 'u', 'U', 'y', 'Y', '@' }; /* 4 bits */
static char consonants1[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm',
        'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'z',
        'B', 'D', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P',
        'R', 'S' }; /* 5 bits */
static char consonants2[] = { 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm',
        'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'z',
        'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M',
        'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Z',
        '1', '2', '5', '6', '7', '8', '9', '!', '#', '$',
        '%', '^', '&', '*', '(', ')', '-', '+', '=', '[',
        ']', ';', '.', ',' }; /* 6 bits */

static int
get_entropy_bits(char *buf, int nbits)
{
        int fd;
        int rv;
        int offset = 0;
        int bytes = (nbits + 7) / 8; /* round up on division */

        fd = open(PATH_DEV_URANDOM, O_RDONLY);
        if (fd == -1)
                return -1;

        while (bytes > 0) {
                rv = read(fd, buf + offset, bytes);

                if (rv < 0) {
                        if (errno == EINTR) continue;
                        (void)close(fd);
                        return -1;
                }
                if (rv == 0) {
                        (void)close(fd);
                        return -1;
                }

                offset += rv;
                bytes -= rv;
        }

        (void)close(fd);
        return 0;
}

static unsigned int
consume_entropy(char *buf, int bits, int *remaining, int *offset)
{
        unsigned int low = (unsigned char)buf[*offset/8];
        unsigned int high = 0;

        if (remaining)
                *remaining -= bits;

        low >>= *offset % 8;
        low &= (1 << bits) - 1;

        if (8 - *offset % 8 < bits) {
               high = (unsigned char)buf[*offset/8 + 1];
               high &= (1 << (bits - (8 - *offset % 8))) - 1;
               high <<= 8 - *offset % 8;
               low |= high;
        }

        *offset += bits;
        return low;    
}

/* generate a random password according to the settings */
int
pwquality_generate(pwquality_settings_t *pwq, int entropy_bits, char **password)
{
        char entropy[PWQ_MAX_ENTROPY_BITS/8 + 1];
        char *tmp;
        int maxlen;
        int try = 0;

        *password = NULL;

        if (entropy_bits > PWQ_MAX_ENTROPY_BITS)
                entropy_bits = PWQ_MAX_ENTROPY_BITS;

        if (entropy_bits < PWQ_MIN_ENTROPY_BITS)
                entropy_bits = PWQ_MIN_ENTROPY_BITS;

        /* overestimate here only 9 bits per syllable of 3 characters */
        maxlen = (entropy_bits + 8) / 9 * 3 + 1;

        tmp = malloc(maxlen);
        if (tmp == NULL) {
                return PWQ_ERROR_MEM_ALLOC;
        }

        do {
                int offset = 0;
                int remaining = entropy_bits;
                char *ptr;

                memset(tmp, '\0', maxlen);
                /* read one more byte for rounding overflow during generation
                   and for at most every 9th bit we also drop one bit */
                if (get_entropy_bits(entropy, entropy_bits +
                                              (entropy_bits+8)/9 + 8) < 0) {
                        free(tmp);
                        return PWQ_ERROR_RNG;
                }

                ptr = tmp;
                while (remaining > 0) {
                        unsigned int idx;

                        if (consume_entropy(entropy, 1, NULL, &offset)) {
                                idx = consume_entropy(entropy, 6, &remaining, &offset);
                                *ptr = consonants2[idx];
                                ++ptr;
                                if (remaining < 0)
                                        break;
                        }

                        idx = consume_entropy(entropy, 4, &remaining, &offset);
                        *ptr = vowels[idx];
                        ++ptr;
                        if (remaining < 0)
                                break;

                        idx = consume_entropy(entropy, 5, &remaining, &offset);
                        *ptr = consonants1[idx];
                        ++ptr;
                }
        } while (pwquality_check(pwq, tmp, NULL, NULL, NULL) < 0 &&
                 ++try < PWQ_NUM_GENERATION_TRIES);

        /* clean up */
        memset(entropy, '\0', sizeof(entropy));

        if (try >= PWQ_NUM_GENERATION_TRIES) {
                free(tmp);
                return PWQ_ERROR_GENERATION_FAILED;
        }

        *password = tmp;
        tmp = NULL;
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
