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
#include <grp.h>
#include <unistd.h>
#include <alloca.h>
#include <errno.h>

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
        distances = malloc(sizeof(int*) * (m + 1));
        if (distances == NULL)
                return -1;

        for (i = 0; i <= m; i++) {
                distances[i] = malloc(sizeof(int) * (n + 1));
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
similar(pwquality_settings *pwq,
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
numclass(pwquality_settings *pwq,
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
simple(pwquality_settings *pwq, const char *new, void **auxerror)
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
consecutive(pwquality_settings *pwq, const char *new, void **auxerror)
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

static int sequence(pwquality_settings *pwq, const char *new, void **auxerror)
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
usercheck(pwquality_settings *pwq, const char *new,
          char *user)
{
        char *f, *b;
        int dist;

        if (strstr(new, user) != NULL)
                return 1;

        dist = distance(new, user);
        if (dist >= 0 && dist < PWQ_DEFAULT_DIFF_OK)
                return 1;

        /* now reverse the username, we can do that in place
                as it is strdup-ed */
        f = user;
        b = user + strlen(user) - 1;
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
wordlistcheck(pwquality_settings *pwq, const char *new,
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
gecoscheck(pwquality_settings *pwq, const char *new,
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

static inline void
create_subst_table(const char *trivial_subst_parameters,char *table)
{
	char b = 0x0;
	register char *t = table;
	for(register int i = 0; i < 0x100; *t = i, ++t, ++i);
	for(register const char *p = trivial_subst_parameters; *p ;++p) {
		const char c = *p;
		if (!b) {
			b = c;
		}

		if (c != ' ') {
			table[c] = b;
		} else {
			 b = 0x0;
		}
	}
}

static inline void
str_convert(const char *table,const char *word, char *converted)
{
	register const char *s = word;
	register char *d = converted;
	for(;*s;*d=table[*s],++d,++s);
	*d = '\0';
}

static char *
x_strdup(const char *string)
{
        if (!string)
                return NULL;
        return strdup(string);
}

static int
password_check(pwquality_settings *pwq,
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

        if (!rv && usermono && usercheck(pwq, newmono, usermono))
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
password_score(pwquality_settings *pwq, const char *password)
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

/* Try to convert the password using a leet speak table then ask to the cracklib dictionary to check if the resulting string is found*/
static int leet_speak_dictionary_check(pwquality_settings *pwq,const char *password,const char *oldpassword, const char *user, void **auxerror) {
	/*
	 * First version: use the first matching pattern in alphabetical order
	 * Table to be completed, some patterns are probably missing
	 */
	static const char *table[] = {
			/*A*/"4\0" "/\\\0" "@\0" "∂\0" "/-\\\0" "|-\\\0" "^" "ci" "\0",
			/*B*/"8\0" "13\0" "|3\0" "ß\0" "\0",
			/*C*/"(\0" "¢\0" "<\0" "[\0" "©\0" "\0",
			/*D*/"[)\0"	"|>\0"  "|)\0" "|]" "\0",
			/*E*/"3\0" "€\0" "є" "[-" "\0",
			/*F*/"|=\0"	"/=" "\0",
			/*G*/"6\0" "(_+\0" "\0",
			/*H*/"#\0" "/-/\0" "[-]\0" "]-[\0" ")-(\0" "(-)\0" ":-:\0" "|~|\0" "|-|\0" "]~[\0" "}{\0" "\0",
			/*I*/"1\0" "!\0" "|\0"	"][\0" "]\0" ":\0" "\0",
			/*J*/"_|\0" "_/\0" "¿\0" "\0",
			/*K*/"|X\0" "|<\0"	"|{\0" "ɮ\0" "\0",
			/*L*/"1\0" "£\0" "1_\0" "ℓ\0" "|_\0" "[_\0" "\0",
			/*M*/"|V|\0" "|\\/|\0" "/\\/\\\0"	"/V\\\0" "\0",
			/*N*/"|V\0" "|\\|\0" "/\\/\0" "[\\]\0" "/V\0" "\0",
			/*O*/"[]\0" "0\0" "()\0" "°\0" "\0",
			/*P*/"|*\0"	"|o\0" "|º\0"  "|°\0" "/*\0" "\0",
			/*Q*/"¶\0"	"(_,)\0"  "()_\0" "0_\0" "°|\0" "<|\0" "0.\0" "\0",
			/*R*/"2\0" "|?\0" "/2\0" "®\0" "Я\0" "|2\0" "\0",
			/*S*/"5\0" "$\0" "§\0" "_/¯\0" "\0",
			/*T*/"7\0" "†\0" "¯|¯\0" "\0",
			/*U*/"(_)\0" "|_|\0" "L|\0" "µ\0" "\0",
			/*V*/"\\/\0" "|/\0" "\0",
			/*W*/"\\/\\/\0"	"vv\0" "'//\0" "\\^/\0" "\\V/\0" "\\|/\0" "\\_|_/\0" "\\_:_/\0" "\0",
			/*X*/"><\0"	"}{\0"  "×\0" ")(\0" "\0",
			/*Y*/"`/\0"	"φ\0" "¥\0" "'/\0" "\0",
			/*Z*/"≥\0" "7_\0" ">_\0" "\0"
	};
	int score = 0;
	const size_t n = strlen(password);
	char converted[n+1];
	register const char *r = password;
	register char *w = converted;
	const char * const end = password + n;
	memset(converted,0,sizeof(converted));
	const char ** const table_end = table + sizeof(table)/sizeof(table[0]);
	for(;r < end;w++,r++) {
		//printf("New character (%c)\n",*r);
		*w = tolower(*r);
		for(const char **pos = table;pos < table_end;pos++) {
			//printf("\tNew table entry %c \n",'a' + (pos - table));
			for(const char *pattern = *pos;*pattern != '\0'; pattern+= (strlen(pattern)+1)) {
				//printf("\t\tNew pattern entry\n");
				const size_t pattern_size = strlen(pattern);
				if (strncmp(pattern,r,pattern_size) == 0) {
					*w = 'a' + (pos - table);
					r += (pattern_size - 1);
					break;
				}
			} // for(const char *pattern = *pos;*pattern != '\0'; pattern+= (strlen(pattern)+1))
			if ((*w) != (*r)) {
				break;
			}
		} // for(const char **pos = table;pos < table_end;pos++)
	} // for(;r < end;w++,r++)
	//printf("converted = %s\n",converted);

	const char *msg = FascistCheck(converted, pwq->dict_path);
	if (msg) {
		if (auxerror) {
			*auxerror = (void *)msg;
		}
		score = PWQ_ERROR_LEET_SPEAK_DICT;
	} else {
		if (password_check(pwq, converted, oldpassword, user, auxerror) != 0) {
			score = PWQ_ERROR_LEET_SPEAK_DICT;
		}

	}

	return score;
}

/*
 * Look for the right profile for this user
 */
#define OVECCOUNT 30    /* should be a multiple of 3 */
static int
match(const char *string,pcre *regex) {
	int match_regex = 0;
	int ovector[OVECCOUNT];
	const size_t subject_length = strlen(string);

	const int nb_match = pcre_exec(
		regex,                   /* the compiled pattern */
		NULL,                 /* no extra data - we didn't study the pattern */
		string,              /* the subject string */
		subject_length,       /* the length of the subject */
		0,                    /* start at offset 0 in the subject */
		PCRE_ANCHORED,                    /* default options */
		ovector,              /* output vector for substring information */
		OVECCOUNT);           /* number of elements in the output vector */
	if (nb_match == 1) {
		if (subject_length == ovector[nb_match]) {
			match_regex = 1;
		}
	} /*else if (PCRE_ERROR_NOMATCH == nb_match) {
		printf("Don't match !\n");
	} else {
		 printf("Matching error %d\n", nb_match);
	}*/
	return match_regex;
}

static int
get_user_primary_groupname(const char *user, char *groupname) {
	int error = EXIT_SUCCESS;
	size_t buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	char pwd_buffer[buffer_size];
	struct passwd pwd;
	struct passwd *result = NULL;
	error = getpwnam_r(user, &pwd, pwd_buffer, buffer_size, &result);
	if (result) {
		struct group grp;
		struct group *grp_result = NULL;
		buffer_size = sysconf(_SC_GETGR_R_SIZE_MAX);
		char grp_buffer[buffer_size];
		error = getgrgid_r(pwd.pw_gid,&grp,grp_buffer, buffer_size,&grp_result);
		if (grp_result) {
			strcpy(groupname,grp.gr_name);
		} else if (0 == error) {
			error = ENOENT;
		}
	} else if (0 == error) {
		error = ENOENT;
	}
	return error;
}

typedef struct string_array_ {
	size_t allocated_size;
	size_t used_size;
	char *buffer;
} string_array;

static inline int
append(const char *string,string_array *array) {
	int error = EXIT_SUCCESS;
	const size_t alloc_size = sysconf(_SC_GETGR_R_SIZE_MAX);
	const size_t n = strlen(string);
	char *current_position = array->buffer + array->used_size;
	if ((n + current_position + 1) > (array->buffer + array->allocated_size)) {
		char * const saved_buffer = array->buffer;
		array->buffer = (char*)realloc(array->buffer,array->allocated_size + alloc_size);
		if (array->buffer) {
			current_position = array->buffer + array->used_size;
			memset(current_position,0,alloc_size);
			array->allocated_size += alloc_size;
		} else {
			error = ENOMEM;
			free(saved_buffer);
		}
	}

	if (array->buffer) {
		strcpy(current_position,string);
		array->used_size += (n + 1);
	}
	return error;
}

static int
get_user_all_groupname(const char *user, char **groupsname) {
	int error = EXIT_SUCCESS;
	size_t buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	char pwd_buffer[buffer_size];
	struct passwd pwd;
	struct passwd *result = NULL;
	error = getpwnam_r(user, &pwd, pwd_buffer, buffer_size, &result);
	if (result) {
		int nbgroups = 0;
		error = getgrouplist(user,pwd.pw_gid,NULL,&nbgroups);
		if (-1 == error) {
			gid_t groups[nbgroups];
			const int rc = getgrouplist(user,pwd.pw_gid,groups,&nbgroups);
			if (rc > 0) {
				buffer_size = sysconf(_SC_GETGR_R_SIZE_MAX);
				const gid_t*  const groups_end = groups + nbgroups;
				char grp_buffer[buffer_size];
				string_array array;
				memset(&array,0,sizeof(array));
				error = EXIT_SUCCESS;
				for(const gid_t* g = groups; ((g < groups_end) && (EXIT_SUCCESS == error));++g) {
					struct group grp;
					struct group *grp_result = NULL;
					error = getgrgid_r(*g,&grp,grp_buffer, buffer_size,&grp_result);
					if (grp_result) {
						error = append(grp.gr_name,&array);
					} else if (0 == error) {
						error = ENOENT;
					}
				}
				if (EXIT_SUCCESS == error) {
					*groupsname = array.buffer;
				} else {
					free(array.buffer);
					array.buffer = NULL;
				}
			} else {
				error = EIO;
			}
		} else {
			error = EIO;
		}
	} else if (0 == error) {
		error = ENOENT;
	}
	return error;
}

static pwquality_settings *
get_user_settings(pwquality_settings_profiles *profiles, const char *user) {
	pwquality_settings *pwq = NULL;
	struct list_head *i = NULL;
	char primary_groupname[128];
	primary_groupname[0] = '\0';
	char *groupsnames = NULL;
	const char *username = (user)?user:"";
	list_for_each_prev(i,profiles) {
		/* look for in reverse order because the first profile is the default one */
		pwquality_settings_profile_node *profile = list_entry(i,pwquality_settings_profile_node,list);
		switch(profile->mode) {
		case Default:
			return &(profile->pwq);
			break;
		case LoginName:
			if (match(username,profile->regex)) {
				return &(profile->pwq);
			}
			break;
		case PrimaryGroupName: {
				int error = EXIT_SUCCESS;
				if (!primary_groupname[0]) {
					error = get_user_primary_groupname(username,primary_groupname);
				}
				if (EXIT_SUCCESS == error) {
					if (match(primary_groupname,profile->regex)) {
						return &(profile->pwq);
					}
				}
			}
			break;
		case MemberOfGroup: {
				int error = EXIT_SUCCESS;
				if (!groupsnames) {
					error = get_user_all_groupname(username,&groupsnames);
				}
				if (EXIT_SUCCESS == error) {
					for(const char *group = groupsnames; *group ; group += (strlen(group) + 1)) {
						if (match(group,profile->regex)) {
							free(groupsnames);
							groupsnames = NULL;
							return &(profile->pwq);
						}
					}
				}
			}
			break;
		/* switch on enum => no default */
		}
	}

	if (groupsnames) {
		free(groupsnames);
		groupsnames = NULL;
	}
	return pwq;
}


/* check the password according to the settings
 * it returns either score <0-100> or negative error number;
 * the old password is optional */
int
pwquality_check(pwquality_settings_t *profiles, const char *password,
        const char *oldpassword, const char *user, void **auxerror)
{
        const char *msg = NULL;
        int score = 0;
        pwquality_settings *pwq = NULL;

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

        /* look for the right password profile for this user */
        pwq = get_user_settings(profiles,user);
        if (pwq) {
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

			if (pwq->trivial_subst) {
				char table[0xFF];
				create_subst_table(pwq->trivial_subst,table);
				const size_t n = strlen(password);
				char converted[n];
				if (pwq->dict_check){
					str_convert(table,password,converted);
					if (strcmp(converted,password) != 0) {
						msg = FascistCheck(password, pwq->dict_path);
						if (msg) {
								if (auxerror)
										*auxerror = (void *)msg;
								return PWQ_ERROR_TRIVIAL_SUBSTITUTION;
						}
					}
				}
			}

			if (pwq->leet_speak_dict_check) {
				score = leet_speak_dictionary_check(pwq,password, oldpassword, user,auxerror);
				if (score != 0) {
					return score;
				}
			}

			score = password_score(pwq, password);
        } else {
        	return PWQ_ERROR_FATAL_FAILURE;
        }

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
