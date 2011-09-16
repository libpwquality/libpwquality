/*
 * libpwquality main API code header
 *
 * Copyright (c) Red Hat, Inc, 2011
 * Copyright (c) Tomas Mraz <tm@t8m.info>, 2011
 *
 * See the end of the file for the License Information
 */

#ifndef PWQUALITY_H
#define PWQUALITY_H

#define PWQ_SETTING_DIFF_OK          1
#define PWQ_SETTING_DIFF_IGNORE      2
#define PWQ_SETTING_MIN_LENGTH       3
#define PWQ_SETTING_DIG_CREDIT       4
#define PWQ_SETTING_UP_CREDIT        5
#define PWQ_SETTING_LOW_CREDIT       6
#define PWQ_SETTING_OTH_CREDIT       7
#define PWQ_SETTING_MIN_CLASS        8
#define PWQ_SETTING_MAX_REPEAT       9
#define PWQ_SETTING_DICT_PATH       10

#define PWQ_MAX_ENTROPY_BITS       256
#define PWQ_MIN_ENTROPY_BITS       56

#define PWQ_ERROR_SUCCESS                        0 /* implicit, not used in the library code */
#define PWQ_ERROR_FATAL_FAILURE                 -1
#define PWQ_ERROR_INTEGER                       -2
#define PWQ_ERROR_CFGFILE_OPEN                  -3
#define PWQ_ERROR_CFGFILE_MALFORMED             -4
#define PWQ_ERROR_UNKNOWN_SETTING               -5
#define PWQ_ERROR_NON_INT_SETTING               -6
#define PWQ_ERROR_NON_STR_SETTING               -7
#define PWQ_ERROR_MEM_ALLOC                     -8
#define PWQ_ERROR_TOO_SIMILAR                   -9
#define PWQ_ERROR_MIN_DIGITS                   -10
#define PWQ_ERROR_MIN_UPPERS                   -11
#define PWQ_ERROR_MIN_LOWERS                   -12
#define PWQ_ERROR_MIN_OTHERS                   -13
#define PWQ_ERROR_MIN_LENGTH                   -14
#define PWQ_ERROR_PALINDROME                   -15
#define PWQ_ERROR_CASE_CHANGES_ONLY            -16
#define PWQ_ERROR_ROTATED                      -17
#define PWQ_ERROR_MIN_CLASSES                  -18
#define PWQ_ERROR_MAX_CONSECUTIVE              -19
#define PWQ_ERROR_EMPTY_PASSWORD               -20
#define PWQ_ERROR_SAME_PASSWORD                -21
#define PWQ_ERROR_CRACKLIB_CHECK               -22
#define PWQ_ERROR_RNG                          -23
#define PWQ_ERROR_GENERATION_FAILED            -24

typedef struct pwquality_settings pwquality_settings_t;

/* returns default pwquality settings to be used in other library calls */
pwquality_settings_t *
pwquality_default_settings(void);

/* frees pwquality settings data */
void
pwquality_free_settings(pwquality_settings_t *pwq);

/* parse the configuration file (if NULL then the default one) */
int
pwquality_read_config(pwquality_settings_t *pwq, const char *cfgfile);

/* useful for setting the options as configured on a pam module
 * command line in form of <opt>=<val> */
int
pwquality_set_option(pwquality_settings_t *pwq, const char *option);

/* set value of an integer setting */
int
pwquality_set_int_value(pwquality_settings_t *pwq, int setting, int value);

/* set value of a string setting */
int
pwquality_set_str_value(pwquality_settings_t *pwq, int setting,
        const char *value);

/* get value of an integer setting, or -1 if setting unknown */
int
pwquality_get_int_value(pwquality_settings_t *pwq, int setting);

/* get value of a string setting, or NULL if setting unknown */
const char *
pwquality_get_str_value(pwquality_settings_t *pwq, int setting);

/* generate a random password of entropy_bits entropy and check it according to
 * the settings */
int
pwquality_generate(pwquality_settings_t *pwq, int entropy_bits,
        char **password);

/* check the password according to the settings
 * it returns either score <0-100>, negative error number,
 * and in case of PWQ_ERROR_CRACKLIB also auxiliary
 * error message returned from cracklib
 * The old password is optional and can be NULL.
 * The score depends on PWQ_SETTING_MIN_LENGTH. If it is set higher,
 * the score for the same passwords will be lower. */ 
int
pwquality_check(pwquality_settings_t *pwq, const char *password,
        const char *oldpassword, const char **error);

#endif /* PWQUALITY_H */

/*
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
