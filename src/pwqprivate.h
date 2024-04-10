/*
 * libpwquality internal header
 *
 * Copyright (c) Red Hat, Inc, 2011,2015
 * Copyright (c) Tomas Mraz <tm@t8m.info>, 2011, 2015
 *
 * See the end of the file for the License Information
 */

#ifndef PWQPRIVATE_H
#define PWQPRIVATE_H

#include "pwquality.h"

struct pwquality_settings {
        int diff_ok;
        int min_length;
        int dig_credit;
        int up_credit;
        int low_credit;
        int oth_credit;
        int min_class;
        int max_repeat;
        int max_class_repeat;
        int max_sequence;
        int gecos_check;
        int dict_check;
        int user_check;
        int user_substr;
        int enforcing;
        int retry_times;
        int enforce_for_root;
        int local_users_only;
        char *bad_words;
        char *dict_path;
        char *base_cfgfile;
        char *default_cfgfile;
};

struct setting_mapping {
        const char *name;
        int id;
        int type;
};

#define PWQ_DEFAULT_DIFF_OK      1
#define PWQ_DEFAULT_MIN_LENGTH   8
#define PWQ_DEFAULT_DIG_CREDIT   0
#define PWQ_DEFAULT_UP_CREDIT    0
#define PWQ_DEFAULT_LOW_CREDIT   0
#define PWQ_DEFAULT_OTH_CREDIT   0

#ifdef HAVE_CRACK_H
#define PWQ_DEFAULT_DICT_CHECK   1
#else
#define PWQ_DEFAULT_DICT_CHECK   0
#endif

#define PWQ_DEFAULT_USER_CHECK   1
#define PWQ_DEFAULT_USER_SUBSTR  0
#define PWQ_DEFAULT_ENFORCING    1
#define PWQ_DEFAULT_RETRY_TIMES  1
#define PWQ_DEFAULT_ENFORCE_ROOT 0
#define PWQ_DEFAULT_LOCAL_USERS  0

#define PWQ_TYPE_INT             1
#define PWQ_TYPE_STR             2
#define PWQ_TYPE_SET             3

#define PWQ_BASE_MIN_LENGTH      6 /* used when lower than this value of min len is set */
#define PWQ_NUM_CLASSES          4
#define PWQ_NUM_GENERATION_TRIES 3 /* how many times to try to generate the random password if it fails the check */
#define PWQ_MIN_WORD_LENGTH      4
#define PWQ_MAX_PASSWD_BUF_LEN   16300

#ifndef PWQUALITY_BASE_PATH
#define PWQUALITY_BASE_PATH "/usr/lib"
#endif

#ifndef PWQUALITY_DEFAULT_PATH
#define PWQUALITY_DEFAULT_PATH "/etc"
#endif

#ifndef PWQUALITY_DEFAULT_NAME
#define PWQUALITY_DEFAULT_NAME "security/pwquality.conf"
#endif

#define PWQUALITY_BASE_CFGFILE PWQUALITY_BASE_PATH "/" PWQUALITY_DEFAULT_NAME
#define PWQUALITY_DEFAULT_CFGFILE PWQUALITY_DEFAULT_PATH "/" PWQUALITY_DEFAULT_NAME

#endif /* PWQPRIVATE_H */

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
