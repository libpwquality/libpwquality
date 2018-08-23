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

#ifdef __cplusplus
extern "C" {
#endif

#define PWQ_SETTING_DIFF_OK          1
#define PWQ_SETTING_MIN_LENGTH       3
#define PWQ_SETTING_DIG_CREDIT       4
#define PWQ_SETTING_UP_CREDIT        5
#define PWQ_SETTING_LOW_CREDIT       6
#define PWQ_SETTING_OTH_CREDIT       7
#define PWQ_SETTING_MIN_CLASS        8
#define PWQ_SETTING_MAX_REPEAT       9
#define PWQ_SETTING_DICT_PATH       10
#define PWQ_SETTING_MAX_CLASS_REPEAT 11
#define PWQ_SETTING_GECOS_CHECK     12
#define PWQ_SETTING_BAD_WORDS       13
#define PWQ_SETTING_MAX_SEQUENCE    14
#define PWQ_SETTING_DICT_CHECK      15
#define PWQ_SETTING_USER_CHECK      16
#define PWQ_SETTING_ENFORCING       17
#define PWQ_SETTING_RETRY_TIMES     18
#define PWQ_SETTING_ENFORCE_ROOT    19
#define PWQ_SETTING_LOCAL_USERS     20

#define PWQ_MAX_ENTROPY_BITS       256
#define PWQ_MIN_ENTROPY_BITS       56

#define PWQ_MAX_ERROR_MESSAGE_LEN  256

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
#define PWQ_ERROR_USER_CHECK                   -25
#define PWQ_ERROR_GECOS_CHECK                  -26
#define PWQ_ERROR_MAX_CLASS_REPEAT             -27
#define PWQ_ERROR_BAD_WORDS                    -28
#define PWQ_ERROR_MAX_SEQUENCE                 -29

typedef struct pwquality_settings pwquality_settings_t;

/* Return default pwquality settings to be used in other library calls. */
pwquality_settings_t *
pwquality_default_settings(void);

/* Free pwquality settings data. */
void
pwquality_free_settings(pwquality_settings_t *pwq);

/* Parse the configuration file (if cfgfile is NULL then the default one).
 * If auxerror is not NULL it also possibly returns auxiliary error information
 * that must be passed into pwquality_strerror() function.
 * New in 1.3.0: First tries to parse all *.conf configuration files from
 *   <cfgfile>.d directory if it exists. Order of parsing determines what
     values will be in effect - the latest wins. */
int
pwquality_read_config(pwquality_settings_t *pwq, const char *cfgfile,
        void **auxerror);

/* Useful for setting the options as configured on a pam module
 * command line in form of <opt>=<val> */
int
pwquality_set_option(pwquality_settings_t *pwq, const char *option);

/* Set value of an integer setting. */
int
pwquality_set_int_value(pwquality_settings_t *pwq, int setting, int value);

/* Set value of a string setting. */
int
pwquality_set_str_value(pwquality_settings_t *pwq, int setting,
        const char *value);

/* Get value of an integer setting. */
int
pwquality_get_int_value(pwquality_settings_t *pwq, int setting, int *value);

/* Get value of a string setting.
 * The caller must copy the string before another calls that can
 * manipulate the pwq settings object.
 */
int
pwquality_get_str_value(pwquality_settings_t *pwq, int setting, const char **value);

/* Generate a random password of entropy_bits entropy and check it according to
 * the settings. */
int
pwquality_generate(pwquality_settings_t *pwq, int entropy_bits,
        char **password);

/* Check the password according to the settings.
 * It returns either score <0-100>, negative error number,
 * and possibly also auxiliary error information that must be
 * passed into pwquality_strerror() function.
 * The old password is optional and can be NULL.
 * The user is used for checking the password against user name
 * and potentially other passwd information and can be NULL.
 * The auxerror can be NULL - in that case the auxiliary error information
 * is not returned.
 * Not passing the *auxerror into pwquality_strerror() can lead to memory leaks.
 * The score depends on PWQ_SETTING_MIN_LENGTH. If it is set higher,
 * the score for the same passwords will be lower. */ 
int
pwquality_check(pwquality_settings_t *pwq, const char *password,
        const char *oldpassword, const char *user, void **auxerror);

/* Translate the error code and auxiliary message into a localized
 * text message.
 * If buf is NULL it uses an internal static buffer which
 * makes the function non-reentrant in that case.
 * The returned pointer is not guaranteed to point to the buf. */
const char *
pwquality_strerror(char *buf, size_t len, int errcode, void *auxerror);

#ifdef __cplusplus
}
#endif

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
