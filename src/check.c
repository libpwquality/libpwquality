/*
 * libpwquality main API code for quality checking
 *
 * See the end of the file for Copyright and License Information
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <crack.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

#include "pwquality.h"
#include "pwqprivate.h"

#ifdef MIN
#undef MIN
#endif
#define MIN(_a, _b) (((_a) < (_b)) ? (_a) : (_b))

/* Helper functions */

/*
 * test for a palindrome - like `R A D A R' or `M A D A M'
 */
static int
palindrome(const char *new)
{
        int i, j;

        i = strlen (new);

        for (j = 0; j < i; j++)
                if (new[i - j - 1] != new[j])
                        return 0;

        return 1;
}

/*
 * Calculate how different two strings are in terms of the number of
 * character removals, additions, and changes needed to go from one to
 * the other
 */

static int 
distdifferent(const char *old, const char *new,
              size_t i, size_t j)
{
        char c, d;

        if ((i == 0) || (strlen(old) < i)) {
                c = 0;
        } else {
                c = old[i - 1];
        }

        if ((j == 0) || (strlen(new) < j)) {
                d = 0;
        } else {
                d = new[j - 1];
        }
        return (c != d);
}

static int
distcalculate(int **distances, const char *old, const char *new,
              size_t i, size_t j)
{
        int tmp = 0;

        if (distances[i][j] != -1) {
                return distances[i][j];
        }

        tmp = distcalculate(distances, old, new, i - 1, j - 1);
        tmp = MIN(tmp, distcalculate(distances, old, new, i, j - 1));
        tmp = MIN(tmp, distcalculate(distances, old, new, i - 1,     j));
        tmp += distdifferent(old, new, i, j);

        distances[i][j] = tmp;

        return tmp;
}

static int
distance(const char *old, const char *new)
{
        int **distances = NULL;
        size_t m, n, i, j;
        int r = -1;

        m = strlen(old);
        n = strlen(new);
        distances = calloc(m + 1, sizeof(int*));
        if (distances == NULL)
                return -1;

        for (i = 0; i <= m; i++) {
                distances[i] = calloc(n + 1, sizeof(int));
                if (distances[i] == NULL)
                        goto allocfail;

                for(j = 0; j <= n; j++) {
                        distances[i][j] = -1;
                }
        }

        for (i = 0; i <= m; i++) {
                distances[i][0] = i;
        }

        for (j = 0; j <= n; j++) {
                distances[0][j] = j;
        }

        r = distcalculate(distances, old, new, m, n);

allocfail:
        for (i = 0; i <= m; i++) {
                if (distances[i]) {
                        memset(distances[i], 0, sizeof(int) * (n + 1));
                        free(distances[i]);
                }
        }
        free(distances);

        return r;
}

static int
similar(pwquality_settings_t *pwq,
        const char *old, const char *new)
{
        int dist;

        dist = distance(old, new);

        if (dist < 0)
                return PWQ_ERROR_MEM_ALLOC;

        if (dist >= pwq->diff_ok) {
                return 0;
        }

        if (strlen(new) >= (strlen(old) * 2)) {
                return 0;
        }

        /* passwords are too similar */
        return PWQ_ERROR_TOO_SIMILAR;
}

/*
 * count classes of charecters
 */

static int
numclass(pwquality_settings_t *pwq,
         const char *new)
{
        int digits = 0;
        int uppers = 0;
        int lowers = 0;
        int others = 0;
        int total_class;
        int i;

        for (i = 0; new[i]; i++) {
                if (isdigit(new[i]))
                        digits = 1;
                else if (isupper(new[i]))
                        uppers = 1;
                else if (islower(new[i]))
                        lowers = 1;
                else
                        others = 1;
        }

        total_class = digits + uppers + lowers + others;

        return total_class;
}

/*
 * a nice mix of characters
 * the credit (if positive) is a maximum value that is subtracted from
 * the minimum allowed size of the password if letters of the class are
 * present in the password
 */
static int
simple(pwquality_settings_t *pwq, const char *new, void **auxerror)
{
        int digits = 0;
        int uppers = 0;
        int lowers = 0;
        int others = 0;
        int size;
        int i;
        enum { NONE, DIGIT, UCASE, LCASE, OTHER } prevclass = NONE;
        int sameclass = 0;

        for (i = 0; new[i]; i++) {
                if (isdigit(new[i])) {
                        digits++;
                        if (prevclass != DIGIT) {
                                prevclass = DIGIT;
                                sameclass = 1;
                        } else
                                sameclass++;
                }
                else if (isupper(new[i])) {
                        uppers++;
                        if (prevclass != UCASE) {
                                prevclass = UCASE;
                                sameclass = 1;
                        } else
                                sameclass++;
                }
                else if (islower(new[i])) {
                        lowers++;
                        if (prevclass != LCASE) {
                                prevclass = LCASE;
                                sameclass = 1;
                        } else
                                sameclass++;
                }
                else {
                        others++;
                        if (prevclass != OTHER) {
                                prevclass = OTHER;
                                sameclass = 1;
                        } else
                                sameclass++;
                }
                if (pwq->max_class_repeat > 1 && sameclass > pwq->max_class_repeat) {
                        if (auxerror)
                                *auxerror = (void *)(long)pwq->max_class_repeat;
                        return PWQ_ERROR_MAX_CLASS_REPEAT;
                }
        }

        if ((pwq->dig_credit >= 0) && (digits > pwq->dig_credit))
                digits = pwq->dig_credit;

        if ((pwq->up_credit >= 0) && (uppers > pwq->up_credit))
                uppers = pwq->up_credit;

        if ((pwq->low_credit >= 0) && (lowers > pwq->low_credit))
                lowers = pwq->low_credit;

        if ((pwq->oth_credit >= 0) && (others > pwq->oth_credit))
                others = pwq->oth_credit;

        size = pwq->min_length;

        if (pwq->dig_credit >= 0)
                size -= digits;
        else if (digits < -pwq->dig_credit) {
                if (auxerror)
                        *auxerror = (void *)(long)-pwq->dig_credit;
                return PWQ_ERROR_MIN_DIGITS;
        }

        if (pwq->up_credit >= 0)
                size -= uppers;
        else if (uppers < -pwq->up_credit) {
                if (auxerror)
                        *auxerror = (void *)(long)-pwq->up_credit;
                return PWQ_ERROR_MIN_UPPERS;
        }

        if (pwq->low_credit >= 0)
                size -= lowers;
        else if (lowers < -pwq->low_credit) {
                if (auxerror)
                        *auxerror = (void *)(long)-pwq->low_credit;
                return PWQ_ERROR_MIN_LOWERS;
        }

        if (pwq->oth_credit >= 0)
                size -= others;
        else if (others < -pwq->oth_credit) {
                if (auxerror)
                        *auxerror = (void *)(long)-pwq->oth_credit;
                return PWQ_ERROR_MIN_OTHERS;
        }

        if (size <= i)
                return 0;

        if (auxerror)
                *auxerror = (void *)(long)size;

        return PWQ_ERROR_MIN_LENGTH;
}

/*
 * too many same consecutive characters
 */

static int
consecutive(pwquality_settings_t *pwq, const char *new, void **auxerror)
{
        char c;
        int i;
        int same;

        if (pwq->max_repeat == 0)
                return 0;

        for (i = 0; new[i]; i++) {
                if (i > 0 && new[i] == c) {
                        ++same;
                        if (same > pwq->max_repeat) {
                                if (auxerror)
                                        *auxerror = (void *)(long)pwq->max_repeat;
                                return 1;
                        }
                } else {
                        c = new[i];
                        same = 1;
                }
        }
        return 0;
}

static int sequence(pwquality_settings_t *pwq, const char *new, void **auxerror)
{
        char c;
        int i;
        int sequp = 1;
        int seqdown = 1;

        if (pwq->max_sequence == 0)
                return 0;

        if (new[0] == '\0')
                return 0;

        for (i = 1; new[i]; i++) {
                c = new[i-1];
                if (new[i] == c+1) {
                        ++sequp;
                        if (sequp > pwq->max_sequence) {
                                if (auxerror)
                                        *auxerror = (void *)(long)pwq->max_sequence;
                                return 1;
                        }
                        seqdown = 1;
                } else if (new[i] == c-1) {
                        ++seqdown;
                        if (seqdown > pwq->max_sequence) {
                                if (auxerror)
                                        *auxerror = (void *)(long)pwq->max_sequence;
                                return 1;
                        }
                        sequp = 1;
                } else {
                        sequp = 1;
                        seqdown = 1;
                }
        }
        return 0;
}

static int
usercheck(pwquality_settings_t *pwq, const char *new,
          char *user)
{
        char *f, *b;
        int dist, userlen = strlen(user);

        /* No point to check for username in password in 1-3 char
         * usernames; it will be contained one way or another anyway. */
        if (userlen < PWQ_MIN_WORD_LENGTH)
                return 0;

        if (strstr(new, user) != NULL)
                return 1;

        dist = distance(new, user);
        if (dist >= 0 && dist < PWQ_DEFAULT_DIFF_OK)
                return 1;

        /* now reverse the username, we can do that in place
                as it is strdup-ed */
        f = user;
        b = user + userlen - 1;
        while (f < b) {
                char c;

                c = *f;
                *f = *b;
                *b = c;
                --b;
                ++f;
        }

        if (strstr(new, user) != NULL)
                return 1;

        dist = distance(new, user);
        if (dist >= 0 && dist < PWQ_DEFAULT_DIFF_OK)
                return 1;

        return 0;
}

static char *
str_lower(char *string)
{
	char *cp;

	if (!string)
		return NULL;

	for (cp = string; *cp; cp++)
		*cp = tolower(*cp);
	return string;
}

static int
wordlistcheck(pwquality_settings_t *pwq, const char *new,
              const char *wordlist)
{
        char *list;
        char *p;
        char *next;

        if (wordlist == NULL)
                return 0;

        if ((list = strdup(wordlist)) == NULL) {
                return PWQ_ERROR_MEM_ALLOC;
        }

        for (p = list;;p = next + 1) {
                next = strchr(p, ' ');
                if (next)
                        *next = '\0';

                if (strlen(p) >= PWQ_MIN_WORD_LENGTH) {
                        str_lower(p);
                        if (usercheck(pwq, new, p)) {
                                free(list);
                                return PWQ_ERROR_BAD_WORDS;
                        }
                }

                if (!next)
                        break;
        }

        free(list);
        return 0;
}

static int
gecoscheck(pwquality_settings_t *pwq, const char *new,
           const char *user)
{
        struct passwd pwd;
        struct passwd *result;
        char *buf;
        size_t bufsize;
        int rv;

        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1 || bufsize > PWQ_MAX_PASSWD_BUF_LEN)
                bufsize = PWQ_MAX_PASSWD_BUF_LEN;
        buf = malloc(bufsize);
        if (buf == NULL)
                return PWQ_ERROR_MEM_ALLOC;

        if (getpwnam_r(user, &pwd, buf, bufsize, &result) != 0 ||
                result == NULL) {
                free(buf);
                return 0;
        }

        rv = wordlistcheck(pwq, new, result->pw_gecos);
        if (rv == PWQ_ERROR_BAD_WORDS)
                rv = PWQ_ERROR_GECOS_CHECK;

        free(buf);        
        return rv;
}

static char *
x_strdup(const char *string)
{
        if (!string)
                return NULL;
        return strdup(string);
}

static int
password_check(pwquality_settings_t *pwq,
               const char *new, const char *old, const char *user,
               void **auxerror)
{
        int rv = 0;
        char *oldmono = NULL, *newmono, *wrapped = NULL;
        char *usermono = NULL;

        newmono = str_lower(x_strdup(new));
        if (!newmono)
                rv = PWQ_ERROR_MEM_ALLOC;

        if (!rv && user) {
                usermono = str_lower(x_strdup(user));
                if (!usermono)
                        rv = PWQ_ERROR_MEM_ALLOC;
        }

        if (!rv && old) {
                oldmono = str_lower(x_strdup(old));
                if (oldmono)
                        wrapped = malloc(strlen(oldmono) * 2 + 1);
                if (wrapped) {
                        strcpy (wrapped, oldmono);
                        strcat (wrapped, oldmono);
                } else {
                        rv = PWQ_ERROR_MEM_ALLOC;
                }
        }

        if (!rv && palindrome(newmono))
                rv = PWQ_ERROR_PALINDROME;

        if (!rv && oldmono && strcmp(oldmono, newmono) == 0)
                rv = PWQ_ERROR_CASE_CHANGES_ONLY;

        if (!rv && oldmono)
                rv = similar(pwq, oldmono, newmono);

        if (!rv)
                rv = simple(pwq, new, auxerror);

        if (!rv && wrapped && strstr(wrapped, newmono))
                rv = PWQ_ERROR_ROTATED;

        if (!rv && numclass(pwq, new) < pwq->min_class) {
                rv = PWQ_ERROR_MIN_CLASSES;
                if (auxerror) {
                        *auxerror = (void *)(long)pwq->min_class;
                }
        }

        if (!rv && consecutive(pwq, new, auxerror))
                rv = PWQ_ERROR_MAX_CONSECUTIVE;

        if (!rv && sequence(pwq, new, auxerror))
                rv = PWQ_ERROR_MAX_SEQUENCE;

        if (!rv && usermono && pwq->user_check &&
                usercheck(pwq, newmono, usermono))
                rv = PWQ_ERROR_USER_CHECK;

        if (!rv && user && pwq->gecos_check)
                rv = gecoscheck(pwq, newmono, user);

        if (!rv)
                rv = wordlistcheck(pwq, newmono, pwq->bad_words);

        if (newmono) {
                memset(newmono, 0, strlen(newmono));
                free(newmono);
        }

        free(usermono);

        if (oldmono) {
                memset(oldmono, 0, strlen(oldmono));
                free(oldmono);
        }

        if (wrapped) {
                memset(wrapped, 0, strlen(wrapped));
                free(wrapped);
        }

        return rv;
}

/* this algorithm is an arbitrary one, fine-tuned by testing */
static int
password_score(pwquality_settings_t *pwq, const char *password)
{
        int len;
        int score;
        int i;
        int j;
        unsigned char freq[256];
        unsigned char *buf;

        len = strlen(password);

        if ((buf = malloc(len)) == NULL)
                /* should get enough memory to obtain a nice score */
                return PWQ_ERROR_MEM_ALLOC;

        score = (len - pwq->min_length) * 2;

        memcpy(buf, password, len);

        for (j = 0; j < 3; j++) {

                memset(freq, 0, sizeof(freq));

                for (i = 0; i < len - j; i++) {
                        ++freq[buf[i]];
                        if (i < len - j - 1)
                                buf[i] = abs(buf[i] - buf[i+1]);
                }

                for (i = 0; i < sizeof(freq); i++) {
                        if (freq[i])
                                ++score;
                }
        }

        memset(buf, 0, len);
        free(buf);

        score += numclass(pwq, password) * 2;

        score = (score * 100)/(3 * pwq->min_length +
                               + PWQ_NUM_CLASSES * 2);

        score -= 50;

        if (score > 100)
                score = 100;
        if (score < 0)
                score = 0;

        return score;
}

/* check the password according to the settings
 * it returns either score <0-100> or negative error number;
 * the old password is optional */
int
pwquality_check(pwquality_settings_t *pwq, const char *password,
        const char *oldpassword, const char *user, void **auxerror)
{
        const char *msg;
        int score;

        if (auxerror)
                *auxerror = NULL;

        if (password == NULL || *password == '\0') {
                return PWQ_ERROR_EMPTY_PASSWORD;
        }

        if (user && *user == '\0')
                user = NULL;

        if (oldpassword && *oldpassword == '\0')
                oldpassword = NULL;

        if (oldpassword && strcmp(oldpassword, password) == 0) {
                return PWQ_ERROR_SAME_PASSWORD;
        }

        if (pwq->diff_ok == 0)
                oldpassword = NULL;

        score = password_check(pwq, password, oldpassword, user, auxerror);

        if (score != 0)
                return score;

        if (pwq->dict_check) {
                msg = FascistCheck(password, pwq->dict_path);
                if (msg) {
                        if (auxerror)
                                *auxerror = (void *)msg;
                        return PWQ_ERROR_CRACKLIB_CHECK;
                }
        }

        score = password_score(pwq, password);

        return score;
}

/*
 * Copyright (c) Cristian Gafton <gafton@redhat.com>, 1996.
 *                                              All rights reserved
 * Copyright (c) Red Hat, Inc, 2011, 2015
 * Copyright (c) Tomas Mraz <tm@t8m.info>, 2011, 2015
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
 *
 * The following copyright was appended for the long password support
 * added with the libpam 0.58 release:
 *
 * Modificaton Copyright (c) Philip W. Dalrymple III <pwd@mdtsoft.com>
 *       1997. All rights reserved
 *
 * THE MODIFICATION THAT PROVIDES SUPPORT FOR LONG PASSWORD TYPE CHECKING TO
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
