/*
 * libpwquality main API code for quality checking
 *
 * See the end of the file for Copyright and License Information
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>   /* INT_MAX, used for length upper-bound checking */

#ifdef HAVE_CRACK_H
#include <crack.h>
#endif
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
 * Compute the Levenshtein distance between two strings.
 *
 * Iterative Wagner-Fischer DP with two-row rolling array:
 *   - No recursion, constant stack depth, eliminating the original
 *     recursive implementation's stack overflow risk;
 *   - O(min(m,n)) space instead of the original O(m*n) int** matrix;
 *   - Returns the exact edit distance for any input length without
 *     breaking caller semantics.
 */
static int
distance(const char *old, const char *new)
{
        const char *s, *t;          /* s: longer string,  t: shorter string */
        int *prev = NULL;           /* previous row D[i-1][*] */
        int *curr = NULL;           /* current row D[i][*]   */
        int *swaprow;
        size_t m, n, i, j, tmp;
        int r = -1;
        int cost, del, ins, sub;

        m = strlen(old);
        n = strlen(new);

        /*
         * Let s point to the longer string and t to the shorter one.
         * The rolling array is allocated by t's length n, so we take
         * n = min(m,n).  The Levenshtein distance is symmetric, so
         * swapping the arguments does not affect the result.
         */
        if (m < n) {
                s = new;
                t = old;
                tmp = m;
                m = n;
                n = tmp;
        } else {
                s = old;
                t = new;
        }

        /*
         * The upper bound of the distance is max(m,n) = m.
         * The recurrence can produce prev[j] + 1, whose maximum is
         * m + 1, so we must ensure m + 1 <= INT_MAX to avoid integer
         * overflow.  Likewise curr[0] = (int)i requires i <= INT_MAX.
         *
         * Therefore we require m <= INT_MAX - 1.
         * Unreachable for any real-world password (~2 GB string),
         * but kept for strictness.
         */
        if (m > (size_t)(INT_MAX - 1))
                return -1;

        prev = malloc((n + 1) * sizeof(int));
        curr = malloc((n + 1) * sizeof(int));
        if (prev == NULL || curr == NULL)
                goto out;           /* r stays -1; free(NULL) is safe */

        /*
         * Base case: D[0][j] = j.
         * The initial prev row corresponds to i = 0 (empty prefix of s).
         * prev[j] = cost of turning the empty string into t[0..j-1],
         * which equals j insertions.
         */
        for (j = 0; j <= n; j++)
                prev[j] = (int)j;

        /*
         * Main loop: compute D[i][*] row by row.
         * At the start of each iteration, prev = D[i-1][*] (previous row,
         * already known) and curr will be filled in as D[i][*] (current
         * row, to be computed).  After each row, prev and curr are
         * swapped so that prev points to the freshly computed row for
         * the next iteration, while curr reuses the old prev row.
         */
        for (i = 1; i <= m; i++) {
                /*
                 * Base column: D[i][0] = i.
                 * Turning s[0..i-1] into the empty string requires i deletions.
                 */
                curr[0] = (int)i;

                for (j = 1; j <= n; j++) {
                        /*
                         * cost = 0 if s[i-1] == t[j-1] (no substitution needed),
                         * cost = 1 otherwise.
                         */
                        cost = (s[i - 1] != t[j - 1]);

                        /*
                         * Three candidates:
                         *   del = D[i-1][j]   + 1 → delete s[i-1] (above)
                         *   ins = D[i][j-1]   + 1 → insert t[j-1] (left, already computed)
                         *   sub = D[i-1][j-1] + cost → substitute/match (upper-left)
                         *
                         * Using prev (previous row) and curr (current row):
                         *   prev[j]   = D[i-1][j]
                         *   curr[j-1] = D[i][j-1]
                         *   prev[j-1] = D[i-1][j-1]
                         */
                        del = prev[j] + 1;
                        ins = curr[j - 1] + 1;
                        sub = prev[j - 1] + cost;

                        /* D[i][j] = min(del, ins, sub) */
                        curr[j] = MIN(MIN(del, ins), sub);
                }

                /* Roll the rows: prev <- curr, curr <- old prev (reused next round) */
                swaprow = prev;
                prev = curr;
                curr = swaprow;
        }

        /*
         * After the loop, prev points to the m-th row (D[m][*]).
         * D[m][n] is the full edit distance.
         * When m == 0 (both strings empty, or n > 0), the loop body is
         * never entered, prev is still the initial row 0, and prev[n] = n
         * equals the correct distance.
         */
        r = prev[n];

out:
        free(prev);
        free(curr);
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
numclass(const char *new)
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
        const char *allow_classes;
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
                if (pwq->max_class_repeat > 0 && sameclass > pwq->max_class_repeat) {
                        if (auxerror)
                                *auxerror = (void *)(long)pwq->max_class_repeat;
                        return PWQ_ERROR_MAX_CLASS_REPEAT;
                }
        }
        pwquality_get_str_value(pwq, PWQ_SETTING_ALLOW_CLASSES, &allow_classes);
        if (digits > 0) {
            if (strpbrk(allow_classes, "d") == NULL) {
                if (auxerror)
                    *auxerror = strdup("digits");
                return PWQ_ERROR_DISALLOWED_CLASS;
            }
        }
        if (uppers > 0) {
            if (strpbrk(allow_classes, "u") == NULL) {
                if (auxerror)
                    *auxerror = strdup("uppercase");
                return PWQ_ERROR_DISALLOWED_CLASS;
            }
        }
        if (lowers > 0) {
            if (strpbrk(allow_classes, "l") == NULL) {
                if (auxerror)
                    *auxerror = strdup("lowercase");
                return PWQ_ERROR_DISALLOWED_CLASS;
            }
        }
        if (others > 0) {
            if (strpbrk(allow_classes, "o") == NULL) {
                if (auxerror)
                    *auxerror = strdup("other");
                return PWQ_ERROR_DISALLOWED_CLASS;
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
        char c = new[0];
        int i;
        int same = 1;

        if (pwq->max_repeat == 0 || c == '\0')
                return 0;

        for (i = 1; new[i]; i++) {
                if (new[i] == c) {
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
wordcheck(pwquality_settings_t *pwq, const char *new,
          char *word)
{
        char *f, *b;
        int dist, wordlen = strlen(word);

        /* No point to check for word in password for 1-3 char
         * words; it will be contained one way or another anyway. */
        if (wordlen < PWQ_MIN_WORD_LENGTH)
                return 0;

        if (strstr(new, word) != NULL)
                return PWQ_ERROR_BAD_WORDS;

        dist = distance(new, word);
        if (dist >= 0 && dist < PWQ_DEFAULT_DIFF_OK)
                return PWQ_ERROR_BAD_WORDS;

        /* now reverse the wordname, we can do that in place
                as it is strdup-ed */
        f = word;
        b = word + wordlen - 1;
        while (f < b) {
                char c;

                c = *f;
                *f = *b;
                *b = c;
                --b;
                ++f;
        }

        if (strstr(new, word) != NULL)
                return PWQ_ERROR_BAD_WORDS;

        dist = distance(new, word);
        if (dist >= 0 && dist < PWQ_DEFAULT_DIFF_OK)
                return PWQ_ERROR_BAD_WORDS;

        return 0;
}

static int
usercheck(pwquality_settings_t *pwq, const char *new,
          char *user)
{
        int i, userlen;
        int rv = 0;
        char *subuser = calloc(pwq->user_substr+1, sizeof(char));

        if (subuser == NULL) {
                return PWQ_ERROR_MEM_ALLOC;
        }

        userlen = strlen(user);
        if (pwq->user_substr >= PWQ_MIN_WORD_LENGTH &&
            userlen > pwq->user_substr) {
                for(i = 0; !rv && (i <= userlen - pwq->user_substr); i++) {
                        strncpy(subuser, user+i, pwq->user_substr+1);
                        subuser[pwq->user_substr] = '\0';
                        rv = wordcheck(pwq, new, subuser);
                }
        }
        else {
                // if we already tested substrings, there's no need to test
                // the whole username; all substrings would've been found :)
                if (!rv)
                        rv = wordcheck(pwq, new, user);
        }
        // translate wordcheck return
        if (rv == PWQ_ERROR_BAD_WORDS)
                rv = PWQ_ERROR_USER_CHECK;
        free(subuser);
        return rv;
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
                        if (wordcheck(pwq, new, p)) {
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
        long bufsize;
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

        if (!rv && oldmono && strcmp(oldmono, newmono) == 0)
                rv = PWQ_ERROR_CASE_CHANGES_ONLY;

        if (!rv && oldmono)
                rv = similar(pwq, oldmono, newmono);

        if (!rv)
                rv = simple(pwq, new, auxerror);

        if (!rv && wrapped && strstr(wrapped, newmono))
                rv = PWQ_ERROR_ROTATED;

        if (!rv && numclass(new) < pwq->min_class) {
                rv = PWQ_ERROR_MIN_CLASSES;
                if (auxerror) {
                        *auxerror = (void *)(long)pwq->min_class;
                }
        }

        if (!rv && palindrome(newmono))
                rv = PWQ_ERROR_PALINDROME;

        if (!rv && consecutive(pwq, new, auxerror))
                rv = PWQ_ERROR_MAX_CONSECUTIVE;

        if (!rv && sequence(pwq, new, auxerror))
                rv = PWQ_ERROR_MAX_SEQUENCE;

        if (!rv && usermono && pwq->user_check)
                rv = usercheck(pwq, newmono, usermono);

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

                for (i = 0; i < (int)sizeof(freq); i++) {
                        if (freq[i])
                                ++score;
                }
        }

        memset(buf, 0, len);
        free(buf);

        score += numclass(password) * 2;

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

        #ifdef HAVE_CRACK_H
        if (pwq->dict_check) {
                msg = FascistCheck(password, pwq->dict_path);
                if (msg) {
                        if (auxerror)
                                *auxerror = (void *)msg;
                        return PWQ_ERROR_CRACKLIB_CHECK;
                }
        }
        #endif

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
