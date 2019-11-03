/*
 * PAM module for password quality checking using libpwquality
 *
 * See the end of the file for Copyright and License Information
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <limits.h>
#include <syslog.h>
#include <libintl.h>
#include <stdio.h>
#include <pwd.h>
#include <errno.h>
#include "pwquality.h"

/* For Translators: "%s%s" could be replaced with "<service> " or "". */
#define PROMPT1 _("New %s%spassword: ")
/* For Translators: "%s%s" could be replaced with "<service> " or "". */
#define PROMPT2 _("Retype new %s%spassword: ")
#define MISTYPED_PASS _("Sorry, passwords do not match.")

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>

/* argument parsing */
#define PAM_DEBUG_ARG       0x0001

struct module_options {
    int retry_times;
    int enforce_for_root;
    int local_users_only;
    pwquality_settings_t *pwq;
};

#define CO_RETRY_TIMES  1

#define PATH_PASSWD "/etc/passwd"

static int
_pam_parse (pam_handle_t *pamh, struct module_options *opt,
            int argc, const char **argv)
{
    int ctrl = 0;
    int rv;
    pwquality_settings_t *pwq;
    void *auxerror;
    char buf[PWQ_MAX_ERROR_MESSAGE_LEN];

    pwq = pwquality_default_settings();
    if (pwq == NULL)
        return -1;

    /* just log error here */
    if ((rv=pwquality_read_config(pwq, NULL, &auxerror)) != 0)
        pam_syslog(pamh, LOG_ERR,
                   "Reading pwquality configuration file failed: %s",
                   pwquality_strerror(buf, sizeof(buf), rv, auxerror));

    /* step through arguments */
    for (ctrl = 0; argc-- > 0; ++argv) {
        char *ep = NULL;

        if (!strcmp(*argv, "debug"))
            ctrl |= PAM_DEBUG_ARG;
        else if (!strncmp(*argv, "type=", 5))
            pam_set_item (pamh, PAM_AUTHTOK_TYPE, *argv+5);
        else if (!strncmp(*argv, "retry=", 6)) {
            opt->retry_times = strtol(*argv+6, &ep, 10);
            if (!ep || (opt->retry_times < 1))
                opt->retry_times = CO_RETRY_TIMES;
        } else if (!strncmp(*argv, "enforce_for_root", 16)) {
            opt->enforce_for_root = 1;
        } else if (!strncmp(*argv, "local_users_only", 16)) {
            opt->local_users_only = 1;
        } else if (!strncmp(*argv, "difignore=", 10)) {
            /* ignored for compatibility with pam_cracklib */
        } else if (!strncmp(*argv, "reject_username", 15)) {
            /* ignored for compatibility with pam_cracklib */
        } else if (!strncmp(*argv, "authtok_type", 12)) {
            /* for pam_get_authtok, ignore */;
        } else if (!strncmp(*argv, "use_authtok", 11)) {
            /* for pam_get_authtok, ignore */;
        } else if (!strncmp(*argv, "use_first_pass", 14)) {
            /* for pam_get_authtok, ignore */;
        } else if (!strncmp(*argv, "try_first_pass", 14)) {
            /* for pam_get_authtok, ignore */;
        } else if (pwquality_set_option(pwq, *argv)) {
            pam_syslog(pamh, LOG_ERR,
                       "pam_parse: unknown or broken option; %s", *argv);
        }
    }

    opt->pwq = pwq;

    return ctrl;
}

static int
check_local_user (pam_handle_t *pamh,
                  const char *user)
{
    struct passwd pw, *pwp;
    char buf[4096];
    int found = 0;
    FILE *fp;
    int errn;

    fp = fopen(PATH_PASSWD, "r");
    if (fp == NULL) {
        pam_syslog(pamh, LOG_ERR, "unable to open %s: %s",
                   PATH_PASSWD, pam_strerror(pamh, errno));
        return -1;
    }

    for (;;) {
        errn = fgetpwent_r(fp, &pw, buf, sizeof (buf), &pwp);
        if (errn == ERANGE) {
            pam_syslog(pamh, LOG_WARNING, "%s contains very long lines; corrupted?",
                       PATH_PASSWD);
            /* we can continue here as next call will read further */
            continue;
        }
        if (errn != 0)
            break;
        if (strcmp(pwp->pw_name, user) == 0) {
            found = 1;
            break;
        }
    }

    fclose (fp);

    if (errn != 0 && errn != ENOENT) {
        pam_syslog(pamh, LOG_ERR, "unable to enumerate local accounts: %s",
                   pam_strerror(pamh, errn));
        return -1;
    } else {
        return found;
    }
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                 int argc, const char **argv)
{
    int ctrl;
    struct module_options options;

    memset(&options, 0, sizeof(options));
    options.retry_times = CO_RETRY_TIMES;

    ctrl = _pam_parse(pamh, &options, argc, argv);
    if (ctrl < 0)
        return PAM_BUF_ERR;

    if (flags & PAM_PRELIM_CHECK) {
        /* Check for passwd dictionary
         * We cannot do that, since the original path is compiled
         * into the cracklib library and we don't know it.
         */
        pwquality_free_settings(options.pwq);
        return PAM_SUCCESS;
    } else if (flags & PAM_UPDATE_AUTHTOK) {
        int retval;
        const void *oldtoken;
        const char *user;
        int tries;

        retval = pam_get_user(pamh, &user, NULL);
        if (retval != PAM_SUCCESS || user == NULL) {
            if (ctrl & PAM_DEBUG_ARG)
                pam_syslog(pamh, LOG_ERR, "Can not get username");
            pwquality_free_settings(options.pwq);
            return PAM_AUTHTOK_ERR;
        }

        retval = pam_get_item(pamh, PAM_OLDAUTHTOK, &oldtoken);
        if (retval != PAM_SUCCESS) {
            if (ctrl & PAM_DEBUG_ARG)
                pam_syslog(pamh, LOG_ERR, "Can not get old passwd");
            oldtoken = NULL;
        }

        tries = 0;
        while (tries < options.retry_times) {
            void *auxerror;
            const char *newtoken = NULL;

            tries++;

            /* Planned modus operandi:
             * Get a passwd.
             * Verify it against libpwquality.
             * If okay get it a second time.
             * Check to be the same with the first one.
             * set PAM_AUTHTOK and return
             */

            retval = pam_get_authtok_noverify(pamh, &newtoken, NULL);
            if (retval != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_ERR, "pam_get_authtok_noverify returned error: %s",
                           pam_strerror(pamh, retval));
                continue;
            } else if (newtoken == NULL) { /* user aborted password change, quit */
                pwquality_free_settings(options.pwq);
                return PAM_AUTHTOK_ERR;
            }

            if (options.local_users_only && check_local_user (pamh, user) == 0) {
                /* skip the check if a non-local user */
                retval = 0;
            } else {
                /* now test this passwd against libpwquality */
                retval = pwquality_check(options.pwq, newtoken, oldtoken, user, &auxerror);
            }

            if (retval < 0) {
                const char *msg;
                char buf[PWQ_MAX_ERROR_MESSAGE_LEN];
                int enforcing = 1;
                msg = pwquality_strerror(buf, sizeof(buf), retval, auxerror);
                if (ctrl & PAM_DEBUG_ARG)
                    pam_syslog(pamh, LOG_DEBUG, "bad password: %s", msg);
                pam_error(pamh, _("BAD PASSWORD: %s"), msg);
                pwquality_get_int_value(options.pwq, PWQ_SETTING_ENFORCING, &enforcing);

                if (enforcing && (getuid() || options.enforce_for_root ||
                                  (flags & PAM_CHANGE_EXPIRED_AUTHTOK))) {
                    pam_set_item(pamh, PAM_AUTHTOK, NULL);
                    retval = PAM_AUTHTOK_ERR;
                    continue;
                }
            } else {
                if (ctrl & PAM_DEBUG_ARG)
                    pam_syslog(pamh, LOG_DEBUG, "password score: %d", retval);
            }

            retval = pam_get_authtok_verify(pamh, &newtoken, NULL);
            if (retval != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_ERR, "pam_get_authtok_verify returned error: %s",
                           pam_strerror(pamh, retval));
                pam_set_item(pamh, PAM_AUTHTOK, NULL);
                continue;
            } else if (newtoken == NULL) {      /* user aborted password change, quit */
                pwquality_free_settings(options.pwq);
                return PAM_AUTHTOK_ERR;
            }

            pwquality_free_settings(options.pwq);
            return PAM_SUCCESS;
        }

        pwquality_free_settings(options.pwq);
        pam_set_item (pamh, PAM_AUTHTOK, NULL);

        /* if we have only one try, we can use the real reason,
         * else say that there were too many tries. */
        if (options.retry_times > 1)
            return PAM_MAXTRIES;
        else
            return retval;
    } else {
        pwquality_free_settings(options.pwq);
        if (ctrl & PAM_DEBUG_ARG)
            pam_syslog(pamh, LOG_NOTICE, "UNKNOWN flags setting %02X",flags);
    }

    return PAM_SERVICE_ERR;
}



#ifdef PAM_STATIC
/* static module data */
struct pam_module _pam_pwquality_modstruct = {
    "pam_pwquality",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    pam_sm_chauthtok
};
#endif

/*
 * Copyright (c) Cristian Gafton <gafton@redhat.com>, 1996.
 *                                              All rights reserved
 * Copyright (c) Red Hat, Inc, 2011, 2012
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
