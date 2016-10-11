#define _XOPEN_SOURCE 700

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ldap.h>
#include <lber.h>
#include <syslog.h>
#include <pam_ext.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include "pam_param.h"
#include "inih/ini.h"

typedef enum {
  CFG_SHORTEN,
  CFG_LDAP_URI,
  CFG_LDAP_DN,
  CFG_LDAP_PW,
  CFG_ADM_BASE,
  CFG_ADM_SCOPE,
  CFG_ADM_FILT,
  CFG_USR_BASE,
  CFG_USR_SCOPE,
  CFG_USR_FILT,
  CFG_HOST_BASE,
  CFG_HOST_SCOPE,
  CFG_HOST_FILT,
  CFG_MEMB_BASE,
  CFG_MEMB_SCOPE,
  CFG_MEMB_FILT
} cfg_index;

typedef struct {
	const char *section;
	const char *name;
	cfg_index index;
} cfg_line;

config my_config;
char *no_attrs[] = { LDAP_NO_ATTRS, NULL };
int debug = 0;
pam_handle_t *pam = NULL;
char *cfg[10];

/*
 * This function is based on PHP implementation of ldap_escape.
 * See LICENSE-php for copyright info.
 */
char *ldap_escape_filter(const char *filter) {
	char map[256] = {0};
	char unsafe[] = "\\*()\0";
	char hex[] = "0123456789abcdef";
	char *result;
	int i, p = 0;
	size_t len = 1;

	/* map unsafe character */
	while ( i < sizeof(unsafe) ) {
		map[(unsigned char) unsafe[i++]] = 1;
	}

	/* count required memory for the result string */
	for (i = 0; i < sizeof(unsafe); i++) {
		len += (map[(unsigned char) filter[i]]) ? 3 : 1;
	}

	result = (char *) malloc(len);
	for (i = 0; i < strlen(filter); i++) {
		unsigned char v = (unsigned char) filter[i];

		if (map[v]) {
			result[p++] = '\\';
			result[p++] = hex[v >> 4];
			result[p++] = hex[v & 0x0f];
		} else {
			result[p++] = v;
		}
	}

	result[p++] = '\0';
}

/* callback for ini parser */
int handler(void *user, const char *section,
		const char *name, const char *value) {
	static cfg_line cfg_lines[] = {
		{"",       "short_name",  CFG_SHORTEN},
		{"ldap",   "uri",         CFG_LDAP_URI},
		{"ldap",   "binddn",      CFG_LDAP_DN},
		{"ldap",   "bindpw",      CFG_LDAP_PW},
		{"admin",  "base",        CFG_ADM_BASE},
		{"admin",  "scope",       CFG_ADM_SCOPE},
		{"admin",  "filter",      CFG_ADM_FILT},
		{"user",   "base",        CFG_USR_BASE},
		{"user",   "scope",       CFG_USR_SCOPE},
		{"user",   "filter",      CFG_USR_FILT},
		{"host",   "base",        CFG_HOST_BASE},
		{"host",   "scope",       CFG_HOST_SCOPE},
		{"host",   "filter",      CFG_HOST_FILT},
		{"host",   "base",        CFG_HOST_BASE},
		{"host",   "scope",       CFG_HOST_SCOPE},
		{"host",   "filter",      CFG_HOST_FILT},
	};
	static size_t n_lines = sizeof(cfg_lines);
	int i;

	for (i = 0; i < n_lines; i++) {
		if (	!(strcmp(section, cfg_lines[i].section) |
					  strcmp(name,    cfg_lines[i].name)) ) {
			cfg[cfg_lines[i].index] = strdup(value);
		}
	}

	/*
	#define SECTION(s) strcmp(s,section) == 0
	#define NAME(n) strcmp(n,name) == 0
	#define SCOPE(s) strcasecmp(s,value) == 0

	if (SECTION("")) {
		if (NAME("short_name")) my_config.short_name = atoi(value);
	} else if (SECTION("ldap")) {
		if (NAME("uri")) {
			my_config.ldap_uri = strdup(value);
		} else if (NAME("binddn")) {
			my_config.ldap_dn = ( *(char *) value == 0 ) ?  NULL : strdup(value);
		} else if (NAME("bindpw")) {
			my_config.ldap_pw = ( *(char *) value == 0 ) ?  NULL : strdup(value);
		} else {
			return 0;
		}
	} else {
		ldap_query *q;

		if (SECTION("admin")) {
			q = &(my_config.admin);
		} else if (SECTION("user")) {
			q = &(my_config.user);
		} else if (SECTION("host")) {
			q = &(my_config.host);
		} else if (SECTION("membership")) {
			q = &(my_config.membership);
		} else {
			return 0;
		}

		if (NAME("base")) {
			q->base = strdup(value);
		} else if (NAME("scope")) {
			if (SCOPE("base")) {
				q->scope = LDAP_SCOPE_BASE;
			} else if (SCOPE("one")) {
				q->scope = LDAP_SCOPE_ONE;
			} else if (SCOPE("sub")) {
				q->scope = LDAP_SCOPE_SUB;
			} else {
				return 0;
			}
		} else if (NAME("filter")) {
			q->filter = strdup(value);
		} else {
			return 0;
		}
	}
	*/
	return 1;
}

/* remove domain parts from hostname */
void shorten_name(char *host_name, int len) {
	char *c;
	for (c = host_name; c < host_name + len; c++) {
		switch (*c) {
			case '.':	*c = 0;
			case 0:	  return;
		}
	}
}

/* runs an LDAP query, and returns the DN of a single result;
 * fails if more than one result found (collision);
 * returns number of entries found */
int get_single_dn(LDAP *ld, ldap_query *q, char **dn) {
	int rc, n_items = 0;
	LDAPMessage *res = NULL;
	LDAPMessage *first;

	rc = ldap_search_ext_s(ld, q->base, q->scope, q->filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				q->filter, ldap_err2string(rc));
		goto end;
	}

	n_items = ldap_count_entries(ld, res);

	switch (n_items) {
		case 0:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"LDAP search '%s' found no entries.", q->filter);
			}
			break;
		case 1:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"LDAP search '%s' found 1 entry.", q->filter);
			}
			first = ldap_first_entry(ld, res);
			*dn = ldap_get_dn(ld, first);
			break;
		default:
			pam_syslog(pam, LOG_WARNING,
					"LDAP search '%s' found %i entries.", q->filter, n_items);
	}

end:
	if (res) ldap_msgfree(res);
	return n_items;
}

/* printf arguments into LDAP filter */
const char *interpolate_filter(const char *filt_templ, const char *a, const char *b) {
	char *result;
	size_t len = strlen(filt_templ);

	if (a) len += strlen(a);
	if (b) len += strlen(b);

	result = (char *) malloc(++len);
	snprintf(result, len, filt_templ, a, b);
	if (debug) {
		pam_syslog(pam, LOG_DEBUG,
				"Interpolated search filter '%s'", result);
	}

	return result;
}

static inline int get_scope(const char *scope_str) {
	typedef struct {
		const char *kw;
		const int val;
	} scope_type;
	static scope_type scopes[] = {
		{"sub",  LDAP_SCOPE_SUB},
		{"one",  LDAP_SCOPE_ONE},
		{"base", LDAP_SCOPE_BASE}
	};

	int i;
	for (i = 0; i < sizeof(scopes); i++) {
		if (strcasecmp(scope_str, scopes[i].kw) == 0)
			return scopes[i].val;
	}
}

/* returns:
 * PAM_SUCCESS if user is super admin;
 * PAM_IGNORE if not;
 * PAM_USER_UNKNOWN if user DN not found;
 * PAM_AUTH_ERR if search failed or collision found */
int is_super_admin(LDAP *ld, char *user_dn) {
	int rc, result = PAM_AUTH_ERR;
	LDAPMessage *res = NULL;

	interpolate_filter(&my_config.admin, user_dn, NULL);

	rc = ldap_search_ext_s(ld, my_config.admin.base, my_config.admin.scope, my_config.admin.filter,
			no_attrs, 1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				my_config.admin.filter, ldap_err2string(rc));
		goto end;
	}

	result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_IGNORE;

end:
	if (res) ldap_msgfree(res);
	return result;
}

/* returns:
 * PAM_SUCCESS if user is permitted;
 * PAM_PERM_DENIED if not;
 * PAM_AUTH_ERR if search failed or collision found */
int user_permitted(LDAP *ld, char *user_dn) {
	char *host_dn = NULL;
	int rc, count, result = PAM_AUTH_ERR;
	LDAPMessage *res;

	rc = get_single_dn(ld, &my_config.host, &host_dn);
	if (rc != 1) {
		result = PAM_AUTH_ERR;
		goto end;
	}

	interpolate_filter(&my_config.membership, user_dn, host_dn);

	rc = ldap_search_ext_s(ld, my_config.membership.base, my_config.membership.scope, my_config.membership.filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				my_config.membership.filter, ldap_err2string(rc));
		goto end;
	}

	result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_PERM_DENIED;

end:
	if (host_dn) ldap_memfree(host_dn);
	if (res) ldap_msgfree(res);
	return result;
}

int read_config() {
	memset((void *) &cfg, 0, sizeof(cfg));
	return ini_parse(CONFIG_FILE, handler, NULL);
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		int argc, const char **argv) {
	char host_name[HOST_NAME_MAX];
	const char *user_name;
	char *user_dn;
	LDAP *ld;
	struct berval cred;
	int result = PAM_AUTH_ERR, rc, i;

	pam = pamh;

	memset((void *) &my_config, 0, sizeof(my_config));

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "debug")) {
			debug = 1;
			break;
		}
	}

	rc = read_config();
	if (rc) {
		pam_syslog(pam, LOG_CRIT, "Unable to parse ini file");
		return PAM_AUTH_ERR;
	}

	/* get user name from PAM */
	rc = pam_get_item(pamh, PAM_USER, (const void **) &user_name);
	if (rc != PAM_SUCCESS
			|| user_name == NULL
			|| *(const char *)user_name == '\0') {
		pam_syslog(pam, LOG_NOTICE, "Cannot obtain the user name");
		return PAM_USER_UNKNOWN;
	}

	/* connect to LDAP */
	rc = ldap_initialize(&ld, my_config.ldap_uri);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Unable to initialize LDAP library: %s",
				strerror(errno));
		return PAM_AUTH_ERR;
	}

	const int version = LDAP_VERSION3;
	rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
	if (rc != LDAP_OPT_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Unable to request LDAPv3 protocol");
		return PAM_AUTH_ERR;
	}

	cred.bv_val = my_config.ldap_pw;
	cred.bv_len = my_config.ldap_pw ? strlen(my_config.ldap_pw) : 0;

	rc = ldap_sasl_bind_s(ld, my_config.ldap_dn, LDAP_SASL_SIMPLE, &cred,
			NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Unable to bind to LDAP at %s: %s",
				my_config.ldap_uri, ldap_err2string(rc));
		return PAM_AUTH_ERR;
	}

	interpolate_filter(&my_config.user, user_name, NULL);
	rc = get_single_dn(ld, &my_config.user, &user_dn);
	if (rc != 1) {
		if (rc) {
			pam_syslog(pam, LOG_ERR, "Multiple DN found for %s", my_config.user);
			result = PAM_AUTH_ERR;
		} else {
			pam_syslog(pam, LOG_WARNING, "Unable to find the DN for %s", my_config.user);
			result = PAM_USER_UNKNOWN;
		}
		goto end_ldap;
	}

	/* check if is super admin */
	result = is_super_admin(ld, user_dn);
	switch (result) {
		case PAM_SUCCESS:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"%s is a super admin", user_name);
			}
			goto end_ldap;
		case PAM_IGNORE:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"%s is not a super admin, continuing", user_name);
			}
			break;
		default:
			pam_syslog(pam, LOG_ERR,
					"Failed to test if %s is a super admin", user_name);
			goto end_ldap;
	}

	/* get host name */
	rc = gethostname(host_name, HOST_NAME_MAX);
	if (rc) {
		pam_syslog(pam, LOG_ERR, "Unable to determine host name");
		result = PAM_AUTH_ERR;
		goto end_ldap;
	}

	if (my_config.short_name) {
		shorten_name(host_name, HOST_NAME_MAX);
		if (debug) {
			pam_syslog(pam, LOG_DEBUG,
					"Short host name is %s", host_name);
		}
	}

	interpolate_filter(&my_config.host, host_name, NULL);

	/* check if access permitted */
	result = user_permitted(ld, user_dn);

	switch (result) {
		case PAM_SUCCESS:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"%s is permitted on %s", user_name, host_name);
			}
			break;
		case PAM_PERM_DENIED:
			pam_syslog(pam, LOG_WARNING,
					"%s is not permitted on %s", user_name, host_name);
			break;
		case PAM_AUTH_ERR:
			pam_syslog(pam, LOG_ERR,
					"Failed to test if %s is permitted on %s", user_name, host_name);
	}

end_ldap:
	ldap_unbind_ext(ld, NULL, NULL);
	if (user_dn) ldap_memfree(user_dn);
	return result;
}
