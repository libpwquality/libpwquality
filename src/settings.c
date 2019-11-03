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
#include <malloc.h>
#include <crack.h>

#include "pwquality.h"
#include "pwqprivate.h"

static inline pcre* regex_compile(const char* value)
{
    int errorOffset = 0;
    const char* errorMsg = NULL;
    pcre *regex = pcre_compile(value, 0, &errorMsg, &errorOffset, NULL);
    if (!regex) {
        printf("PCRE compilation of %s failed at offset %d: %s\n", value,errorOffset, errorMsg);
    }
    return regex;
}

static inline pwquality_settings_profile_node* new_pwquality_settings_profile_node(const char *name,pwquality_settings_profiles *profiles)
{
    pwquality_settings_profile_node *new_profile = NULL;
    if (list_empty(profiles) || ((strcasecmp(name,"default") != 0) && (name[0]))) {
        new_profile = (pwquality_settings_profile_node *)malloc(sizeof(pwquality_settings_profile_node));
        if (new_profile) {
            memset(new_profile,0,sizeof(pwquality_settings_profile_node));
            new_profile->name = strdup(name);
            if (new_profile->name) {
                new_profile->pwq.diff_ok = PWQ_DEFAULT_DIFF_OK;
                new_profile->pwq.min_length = PWQ_DEFAULT_MIN_LENGTH;
                new_profile->pwq.dig_credit = PWQ_DEFAULT_DIG_CREDIT;
                new_profile->pwq.up_credit = PWQ_DEFAULT_UP_CREDIT;
                new_profile->pwq.low_credit = PWQ_DEFAULT_LOW_CREDIT;
                new_profile->pwq.oth_credit = PWQ_DEFAULT_OTH_CREDIT;
                new_profile->pwq.dict_check = PWQ_DEFAULT_DICT_CHECK;
                new_profile->pwq.user_check = PWQ_DEFAULT_USER_CHECK;
                new_profile->pwq.enforcing = PWQ_DEFAULT_ENFORCING;
                new_profile->pwq.retry_times = PWQ_DEFAULT_RETRY_TIMES;
                new_profile->pwq.enforce_for_root = PWQ_DEFAULT_ENFORCE_ROOT;
                new_profile->pwq.local_users_only = PWQ_DEFAULT_LOCAL_USERS;
                new_profile->pwq.leet_speak_dict_check = PWQ_DEFAULT_LEETSPEAK_DICT_CHECK;
                list_add_tail(&new_profile->list,profiles);
            } else {
                printf("Failed to allocate %zu bytes of memory for a new profile name\n",strlen(name));
            }
        } else {
            printf("Failed to allocate %zu bytes of memory for a new profile\n",sizeof(pwquality_settings_profile_node));
        }
    } else {
        new_profile = list_entry(profiles->next,pwquality_settings_profile_node,list);
    }

    return new_profile;
}

/* returns default pwquality settings to be used in other library calls */
pwquality_settings_t *
pwquality_default_settings(void)
{
    pwquality_settings_profiles *new_profiles = (pwquality_settings_profiles *)malloc(sizeof(pwquality_settings_profiles));
    if (new_profiles) {
        INIT_LIST_HEAD(new_profiles);
        pwquality_settings_profile_node *profile = new_pwquality_settings_profile_node("",new_profiles);
        if (!profile) {
            free(new_profiles);
            new_profiles = NULL;
        }
    }
    return new_profiles;
}

/* frees pwquality settings data */
void
pwquality_free_settings(pwquality_settings_profiles *profiles)
{
    struct list_head *i = NULL;
    struct list_head *t = NULL;

    list_for_each_safe(i,t,profiles) {
#define FREE(x) if (node->x) { free((void*)node->x); node->x = NULL; }
#define FREE2(x) FREE(pwq.x)
        pwquality_settings_profile_node *node = list_entry(i,pwquality_settings_profile_node,list);
        FREE(name);
        if (node->regex) {
            pcre_free(node->regex);
            node->regex = NULL;
        }
        FREE2(bad_words);
        FREE2(dict_path);
        FREE2(trivial_subst);
        list_del(i);
        free(node);
        node = NULL;
#undef FREE
#undef FREE2
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
    { "trivialsubst", PWQ_SETTING_TRIVIAL_SUBST, PWQ_TYPE_STR},
    { "leetspeakcheck",PWQ_SETTING_LEET_SPEAK_DICT_CHECK, PWQ_TYPE_INT},
    { "retry", PWQ_SETTING_RETRY_TIMES, PWQ_TYPE_INT},
    { "enforce_for_root", PWQ_SETTING_ENFORCE_ROOT, PWQ_TYPE_SET},
    { "local_users_only", PWQ_SETTING_LOCAL_USERS, PWQ_TYPE_SET}
};

/* set setting name with value */
static int pwquality_set_int_value_internal(pwquality_settings *pwq, int setting, int value);
static int pwquality_set_str_value_internal(pwquality_settings *pwq, int setting,const char *value);

static int
set_name_value(pwquality_settings *pwq, const char *name, const char *value)
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
                return pwquality_set_int_value_internal(pwq, s_map[i].id,
                                                        (int)val);
            case PWQ_TYPE_STR:
                return pwquality_set_str_value_internal(pwq, s_map[i].id,value);
            case PWQ_TYPE_SET:
                return pwquality_set_int_value_internal(pwq, s_map[i].id,
                                                        1);
            }
        }
    }
    return PWQ_ERROR_UNKNOWN_SETTING;
}

#define PWQSETTINGS_MAX_LINELEN 1023

/* parse a single configuration file*/
int
read_config_file(pwquality_settings_t *profiles, const char *cfgfile, void **auxerror)
{
    FILE *f = NULL;
    char linebuf[PWQSETTINGS_MAX_LINELEN+1];
    int rv = 0;
    pwquality_settings_profile_node *profile = NULL;

    /* move to the last profile */
    struct list_head *pos = profiles->next;
    for(; pos->next != profiles; pos = pos->next);
    profile = list_entry(pos,pwquality_settings_profile_node,list);

    f = fopen(cfgfile, "r");
    if (f == NULL) {
        /* ignore non-existent default config file */
        if (errno == ENOENT && strcmp(cfgfile, PWQUALITY_DEFAULT_CFGFILE) == 0)
            return 0;
        return PWQ_ERROR_CFGFILE_OPEN;
    }

    while (fgets(linebuf, sizeof(linebuf), f) != NULL) {
        size_t len = 0;
        char *ptr = NULL;
        char *name = NULL;
        int eq = 0;

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

        /* check if this line define a new section */
        if (*ptr == '[') {
            for (++ptr; isspace(*ptr); ptr++);
            name = ptr;
            if ((ptr=strchr(name, ']')) != NULL) {
                *ptr = '\0';
                profile = new_pwquality_settings_profile_node(name,profiles);
                continue;
            } else {
                rv = PWQ_ERROR_CFGFILE_MALFORMED;
                break;
            }
        }

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

        if (strcmp("loginname",name) == 0) {
            if (NULL == profile->regex) {
                profile->mode = LoginName;
                profile->regex = regex_compile(ptr);
                if (!profile->regex) {
                    rv = PWQ_ERROR_REGEX;
                    if (auxerror) {
                        *auxerror = strdup(name);
                    }
                    break;
                }
            } else {
                rv = PWQ_ERROR_CFGFILE_MALFORMED;
                break;
            }
        } else if (strcmp("groupname",name) == 0) {
            if (NULL == profile->regex) {
                profile->mode = PrimaryGroupName;
                profile->regex =  regex_compile(ptr);
                if (!profile->regex) {
                    rv = PWQ_ERROR_REGEX;
                    if (auxerror) {
                        *auxerror = strdup(name);
                    }
                    break;
                }
            } else {
                rv = PWQ_ERROR_CFGFILE_MALFORMED;
                break;
            }
        } else if (strcmp("memberof",name) == 0) {
            if (NULL == profile->regex) {
                profile->mode = MemberOfGroup;
                profile->regex =  regex_compile(ptr);
                if (!profile->regex) {
                    rv = PWQ_ERROR_REGEX;
                    if (auxerror) {
                        *auxerror = strdup(name);
                    }
                    break;
                }
            } else {
                rv = PWQ_ERROR_CFGFILE_MALFORMED;
                break;
            }
            break;
        } else if ((rv=set_name_value(&(profile->pwq), name, ptr)) != 0) {
            if (auxerror) {
                *auxerror = strdup(name);
            }
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
pwquality_read_config(pwquality_settings_t *profiles, const char *cfgfile, void **auxerror)
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
            rv = read_config_file(profiles, subcfg, auxerror);
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

    return read_config_file(profiles, cfgfile, auxerror);
}

/* useful for setting the options as configured on a pam module
 * command line in form of <opt>=<val> */
int
pwquality_set_option(pwquality_settings_t *profiles, const char *option)
{
    pwquality_settings_profile_node *node = list_entry(profiles->next,pwquality_settings_profile_node,list);
    pwquality_settings *pwq = &(node->pwq);

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
static int
pwquality_set_int_value_internal(pwquality_settings *pwq, int setting, int value)
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
    case PWQ_SETTING_LEET_SPEAK_DICT_CHECK:
        pwq->leet_speak_dict_check = value;
        break;
    default:
        return PWQ_ERROR_NON_INT_SETTING;
    }

    return 0;
}

int
pwquality_set_int_value(pwquality_settings_t *profiles, int setting, int value)
{
    pwquality_settings_profile_node *node = list_entry(profiles->next,pwquality_settings_profile_node,list);
    pwquality_settings *pwq = &(node->pwq);
    return pwquality_set_int_value_internal(pwq,setting,value);
}

/* set value of a string setting */
static int
pwquality_set_str_value_internal(pwquality_settings *pwq, int setting,
                                 const char *value)
{
    char *dup = NULL;

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
    case PWQ_SETTING_TRIVIAL_SUBST:
        free(pwq->trivial_subst);
        pwq->trivial_subst = dup;
        break;
    default:
        free(dup);
        return PWQ_ERROR_NON_STR_SETTING;
    }

    return 0;
}

int
pwquality_set_str_value(pwquality_settings_t *profiles, int setting, const char *value)
{
    pwquality_settings_profile_node *node = list_entry(profiles->next,pwquality_settings_profile_node,list);
    pwquality_settings *pwq = &(node->pwq);
    return pwquality_set_str_value_internal(pwq,setting,value);
}


/* get value of an integer setting */
int
pwquality_get_int_value(pwquality_settings_t *profiles, int setting, int *value)
{
    pwquality_settings_profile_node *node = list_entry(profiles->next,pwquality_settings_profile_node,list);
    pwquality_settings *pwq = &(node->pwq);

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
    case PWQ_SETTING_LEET_SPEAK_DICT_CHECK:
        *value = pwq->leet_speak_dict_check;
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
pwquality_get_str_value(pwquality_settings_t *profiles, int setting, const char **value)
{
    pwquality_settings_profile_node *node = list_entry(profiles->next,pwquality_settings_profile_node,list);
    pwquality_settings *pwq = &(node->pwq);

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
    case PWQ_SETTING_TRIVIAL_SUBST:
        *value = pwq->trivial_subst;
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
