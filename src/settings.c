/*
 * libpwquality main API code for reading and manipulation of settings
 *
 * See the end of the file for Copyright and License Information
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <crack.h>

#include "pwquality.h"
#include "pwqprivate.h"

/* returns default pwquality settings to be used in other library calls */
pwquality_settings_t *
pwquality_default_settings(void)
{
        pwquality_settings_t *pwq;

        pwq = calloc(1, sizeof(*pwq));
        if (!pwq)
                return NULL;

        pwq->diff_ok = PWQ_DEFAULT_DIFF_OK;
        pwq->min_length = PWQ_DEFAULT_MIN_LENGTH;
        pwq->dig_credit = PWQ_DEFAULT_DIG_CREDIT;
        pwq->up_credit = PWQ_DEFAULT_UP_CREDIT;
        pwq->low_credit = PWQ_DEFAULT_LOW_CREDIT;
        pwq->oth_credit = PWQ_DEFAULT_OTH_CREDIT;
        pwq->dict_check = PWQ_DEFAULT_DICT_CHECK;
        pwq->user_check = PWQ_DEFAULT_USER_CHECK;
        pwq->enforcing = PWQ_DEFAULT_ENFORCING;
        pwq->retry_times = PWQ_DEFAULT_RETRY_TIMES;
        pwq->enforce_for_root = PWQ_DEFAULT_ENFORCE_ROOT;
        pwq->local_users_only = PWQ_DEFAULT_LOCAL_USERS;

        return pwq;
}

/* frees pwquality settings data */
void
pwquality_free_settings(pwquality_settings_t *pwq)
{
        if (pwq) {
                free(pwq->dict_path);
                free(pwq->bad_words);
                free(pwq);
        }
}


static const struct setting_mapping s_map[] = {
 { "difok", PWQ_SETTING_DIFF_OK, PWQ_TYPE_INT},
 { "minlen", PWQ_SETTING_MIN_LENGTH, PWQ_TYPE_INT},
 { "dcredit", PWQ_SETTING_DIG_CREDIT, PWQ_TYPE_INT},
 { "ucredit", PWQ_SETTING_UP_CREDIT, PWQ_TYPE_INT},
 { "lcredit", PWQ_SETTING_LOW_CREDIT, PWQ_TYPE_INT},
 { "ocredit", PWQ_SETTING_OTH_CREDIT, PWQ_TYPE_INT},
 { "minclass", PWQ_SETTING_MIN_CLASS, PWQ_TYPE_INT},
 { "maxrepeat", PWQ_SETTING_MAX_REPEAT, PWQ_TYPE_INT},
 { "maxclassrepeat", PWQ_SETTING_MAX_CLASS_REPEAT, PWQ_TYPE_INT},
 { "maxsequence", PWQ_SETTING_MAX_SEQUENCE, PWQ_TYPE_INT},
 { "gecoscheck", PWQ_SETTING_GECOS_CHECK, PWQ_TYPE_INT},
 { "dictcheck", PWQ_SETTING_DICT_CHECK, PWQ_TYPE_INT},
 { "usercheck", PWQ_SETTING_USER_CHECK, PWQ_TYPE_INT},
 { "enforcing", PWQ_SETTING_ENFORCING, PWQ_TYPE_INT},
 { "badwords", PWQ_SETTING_BAD_WORDS, PWQ_TYPE_STR},
 { "dictpath", PWQ_SETTING_DICT_PATH, PWQ_TYPE_STR},
 { "retry", PWQ_SETTING_RETRY_TIMES, PWQ_TYPE_INT},
 { "enforce_for_root", PWQ_SETTING_ENFORCE_ROOT, PWQ_TYPE_SET},
 { "local_users_only", PWQ_SETTING_LOCAL_USERS, PWQ_TYPE_SET}
};

/* set setting name with value */
static int
set_name_value(pwquality_settings_t *pwq, const char *name, const char *value)
{
        int i;
        long val;
        char *endptr;

        for (i = 0; i < sizeof(s_map)/sizeof(s_map[0]); i++) {
                if (strcasecmp(s_map[i].name, name) == 0) {
                        switch(s_map[i].type) {
                        case PWQ_TYPE_INT:
                                errno = 0;
                                val = strtol(value, &endptr, 10);
                                if (errno != 0 || *value == '\0' ||
                                    *endptr != '\0' || val >= INT_MAX || val <= INT_MIN) {
                                        return PWQ_ERROR_INTEGER;
                                }
                                return pwquality_set_int_value(pwq, s_map[i].id,
                                        (int)val);
                        case PWQ_TYPE_STR:
                                return pwquality_set_str_value(pwq, s_map[i].id,
                                        value);
                        case PWQ_TYPE_SET:
                                return pwquality_set_int_value(pwq, s_map[i].id,
                                        1);
                        }
                }
        }
        return PWQ_ERROR_UNKNOWN_SETTING;
}

#define PWQSETTINGS_MAX_LINELEN 1023

/* parse a single configuration file*/
int
read_config_file(pwquality_settings_t *pwq, const char *cfgfile, void **auxerror)
{
        FILE *f;
        char linebuf[PWQSETTINGS_MAX_LINELEN+1];
        int rv = 0;

        f = fopen(cfgfile, "r");
        if (f == NULL) {
                /* ignore non-existent default config file */
                if (errno == ENOENT && strcmp(cfgfile, PWQUALITY_DEFAULT_CFGFILE) == 0)
                        return 0;
                return PWQ_ERROR_CFGFILE_OPEN;
        }

        while (fgets(linebuf, sizeof(linebuf), f) != NULL) {
                size_t len;
                char *ptr;
                char *name;
                int eq;

                len = strlen(linebuf);
                /* len cannot be 0 unless there is a bug in fgets */
                if (len && linebuf[len - 1] != '\n' && !feof(f)) {
                        (void) fclose(f);
                        return PWQ_ERROR_CFGFILE_MALFORMED;
                }

                if ((ptr=strchr(linebuf, '#')) != NULL) {
                        *ptr = '\0';
                } else {
                        ptr = linebuf + len;
                }

                /* drop terminating whitespace including the \n */
                while (ptr > linebuf) {
                        if (!isspace(*(ptr-1))) {
                                *ptr = '\0';
                                break;
                        }
                        --ptr;
                }

                /* skip initial whitespace */
                for (ptr = linebuf; isspace(*ptr); ptr++);
                if (*ptr == '\0')
                        continue;

                eq = 0;
                name = ptr;
                while (*ptr != '\0') {
                        if (isspace(*ptr) || *ptr == '=') {
                                eq = *ptr == '=';
                                *ptr = '\0';
                                ++ptr;
                                break;
                        }
                        ++ptr;
                }

                while (*ptr != '\0') {
                        if (*ptr != '=' || eq) {
                                if (!isspace(*ptr)) {
                                        break;
                                }
                        } else {
                                eq = 1;
                        }
                        ++ptr;
                }

                if ((rv=set_name_value(pwq, name, ptr)) != 0) {
                        if (auxerror)
                                *auxerror = strdup(name);
                        break;
                }
        }

        (void)fclose(f);
        return rv;
}

static int
filter_conf(const struct dirent *d)
{
        const char *p;

        if ((p = strstr(d->d_name, ".conf")) == NULL)
                return 0;

        if (p[5] != '\0')
                return 0;

        return 1;
}

static int
comp_func(const struct dirent **a, const struct dirent **b)
{
        return strcmp ((*a)->d_name, (*b)->d_name);
}

/* parse the configuration file (if NULL then the default one) */
int
pwquality_read_config(pwquality_settings_t *pwq, const char *cfgfile, void **auxerror)
{
        char *dirname;
        struct dirent **namelist;
        int n;
        int i;
        int rv = 0;

        if (auxerror)
                *auxerror = NULL;
        if (cfgfile == NULL)
                cfgfile = PWQUALITY_DEFAULT_CFGFILE;

        /* read "*.conf" files from "<cfgfile>.d" directory first */

        if (asprintf(&dirname, "%s.d", cfgfile) < 0)
                return PWQ_ERROR_MEM_ALLOC;

        /* we do not care about scandir races here so we use scandir */
        n = scandir(dirname, &namelist, filter_conf, comp_func);

        if (n < 0) {
                namelist = NULL;

                if (errno == ENOMEM) {
                        free(dirname);
                        return PWQ_ERROR_MEM_ALLOC;
                } /* other errors are ignored */
        }

        for (i = 0; i < n; i++) {
                char *subcfg;

                if (rv) {
                        free(namelist[i]);
                        continue;
                }

                if (asprintf(&subcfg, "%s/%s", dirname, namelist[i]->d_name) < 0)
                        rv = PWQ_ERROR_MEM_ALLOC;
                else {
                        rv = read_config_file(pwq, subcfg, auxerror);
                        if (rv == PWQ_ERROR_CFGFILE_OPEN)
                                rv = 0; /* ignore, this one does not modify auxerror */
                        free(subcfg);
                }

                free(namelist[i]);
        }
        free(dirname);
        free(namelist);

        if (rv)
                return rv;

        return read_config_file(pwq, cfgfile, auxerror);
}

/* useful for setting the options as configured on a pam module
 * command line in form of <opt>=<val> */
int
pwquality_set_option(pwquality_settings_t *pwq, const char *option)
{
        char name[80]; /* no options with name longer than that */
        const char *value;
        size_t len;

        value = strchr(option, '=');
        if (value == NULL) {
                len = strlen(option);
                value = option + len;  /* just empty value */
        } else {
                len = value - option;
                ++value;
        }
        if (len > sizeof(name) - 1)
                return PWQ_ERROR_UNKNOWN_SETTING;

        strncpy(name, option, len);
        name[len] = '\0';

        return set_name_value(pwq, name, value);
}

/* set value of an integer setting */
int
pwquality_set_int_value(pwquality_settings_t *pwq, int setting, int value)
{
        switch(setting) {
        case PWQ_SETTING_DIFF_OK:
                pwq->diff_ok = value;
                break;
        case PWQ_SETTING_MIN_LENGTH:
                if (value < PWQ_BASE_MIN_LENGTH)
                        value = PWQ_BASE_MIN_LENGTH;
                pwq->min_length = value;
                break;
        case PWQ_SETTING_DIG_CREDIT:
                pwq->dig_credit = value;
                break;
        case PWQ_SETTING_UP_CREDIT:
                pwq->up_credit = value;
                break;
        case PWQ_SETTING_LOW_CREDIT:
                pwq->low_credit = value;
                break;
        case PWQ_SETTING_OTH_CREDIT:
                pwq->oth_credit = value;
                break;
        case PWQ_SETTING_MIN_CLASS:
                if (value > PWQ_NUM_CLASSES)
                        value = PWQ_NUM_CLASSES;
                pwq->min_class = value;
                break;
        case PWQ_SETTING_MAX_REPEAT:
                pwq->max_repeat = value;
                break;
        case PWQ_SETTING_MAX_CLASS_REPEAT:
                pwq->max_class_repeat = value;
                break;
        case PWQ_SETTING_MAX_SEQUENCE:
                pwq->max_sequence = value;
                break;
        case PWQ_SETTING_GECOS_CHECK:
                pwq->gecos_check = value;
                break;
        case PWQ_SETTING_DICT_CHECK:
                pwq->dict_check = value;
                break;
        case PWQ_SETTING_USER_CHECK:
                pwq->user_check = value;
                break;
        case PWQ_SETTING_ENFORCING:
                pwq->enforcing = value;
                break;
        case PWQ_SETTING_RETRY_TIMES:
                pwq->retry_times = value;
                break;
        case PWQ_SETTING_ENFORCE_ROOT:
                pwq->enforce_for_root = value;
                break;
        case PWQ_SETTING_LOCAL_USERS:
                pwq->local_users_only = value;
                break;
        default:
                return PWQ_ERROR_NON_INT_SETTING;
        }

        return 0;
}

/* set value of a string setting */
int
pwquality_set_str_value(pwquality_settings_t *pwq, int setting,
        const char *value)
{
        char *dup;

        if (value == NULL || *value == '\0') {
                dup = NULL;
        } else {
                dup = strdup(value);
                if (dup == NULL)
                        return PWQ_ERROR_MEM_ALLOC;
        }

        switch(setting) {
        case PWQ_SETTING_BAD_WORDS:
                free(pwq->bad_words);
                pwq->bad_words = dup;
                break;
        case PWQ_SETTING_DICT_PATH:
                free(pwq->dict_path);
                pwq->dict_path = dup;
                break;
        default:
                free(dup);
                return PWQ_ERROR_NON_STR_SETTING;
        }

        return 0;
}

/* get value of an integer setting */
int
pwquality_get_int_value(pwquality_settings_t *pwq, int setting, int *value)
{
        switch(setting) {
        case PWQ_SETTING_DIFF_OK:
                *value = pwq->diff_ok;
                break;
        case PWQ_SETTING_MIN_LENGTH:
                *value = pwq->min_length;
                break;
        case PWQ_SETTING_DIG_CREDIT:
                *value = pwq->dig_credit;
                break;
        case PWQ_SETTING_UP_CREDIT:
                *value = pwq->up_credit;
                break;
        case PWQ_SETTING_LOW_CREDIT:
                *value = pwq->low_credit;
                break;
        case PWQ_SETTING_OTH_CREDIT:
                *value = pwq->oth_credit;
                break;
        case PWQ_SETTING_MIN_CLASS:
                *value = pwq->min_class;
                break;
        case PWQ_SETTING_MAX_REPEAT:
                *value = pwq->max_repeat;
                break;
        case PWQ_SETTING_MAX_CLASS_REPEAT:
                *value = pwq->max_class_repeat;
                break;
        case PWQ_SETTING_MAX_SEQUENCE:
                *value = pwq->max_sequence;
                break;
        case PWQ_SETTING_GECOS_CHECK:
                *value = pwq->gecos_check;
                break;
        case PWQ_SETTING_DICT_CHECK:
                *value = pwq->dict_check;
                break;
        case PWQ_SETTING_USER_CHECK:
                *value = pwq->user_check;
                break;
        case PWQ_SETTING_ENFORCING:
                *value = pwq->enforcing;
                break;
        case PWQ_SETTING_RETRY_TIMES:
                *value = pwq->retry_times;
                break;
        case PWQ_SETTING_ENFORCE_ROOT:
                *value = pwq->enforce_for_root;
                break;
        case PWQ_SETTING_LOCAL_USERS:
                *value = pwq->local_users_only;
                break;
        default:
                return PWQ_ERROR_NON_INT_SETTING;
        }
        return 0;
}

/* get value of a string setting, or NULL if setting unknown */
int
pwquality_get_str_value(pwquality_settings_t *pwq, int setting, const char **value)
{
        switch(setting) {
        case PWQ_SETTING_BAD_WORDS:
                *value = pwq->bad_words;
                break;
        case PWQ_SETTING_DICT_PATH:
                if (pwq->dict_path)
                        *value = pwq->dict_path;
                else
                        *value = GetDefaultCracklibDict();
                break;
        default:
                return PWQ_ERROR_NON_STR_SETTING;
        }
        return 0;
}

/*
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
 */
