#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
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

static char *ldap_escape_filter(const char *filter);
static int ini_callback(void *user, const char *section, const char *name, const char *value);
static inline int get_host_dn(char **dn);
static inline int get_user_dn(const char *raw_username, char **dn);
static inline LDAP *ldap_connect();
static int get_single_dn(const char *base, int scope, const char *filter, char **dn);
static inline int get_scope(const char *scope_str);
static inline int authorize_admin(char *user_dn);
static inline int authorize_user(const char *user_dn, const char *host_dn);
static inline int read_config();

char *no_attrs[] = { LDAP_NO_ATTRS, NULL };
int debug = 0;
pam_handle_t *pam = NULL;
LDAP *ld = NULL;
char *cfg[10];

/*
 * This function is based on PHP implementation of ldap_escape.
 * See LICENSE-php for copyright info.
 */
static char *ldap_escape_filter(const char *filter) {
	char map[256] = {0};
	const char unsafe[] = "\\*()\0";
	const char hex[] = "0123456789abcdef";
	char *result;
	int i = 0, p = 0;
	size_t len = 1;

	/* map unsafe character */
	for (i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
		map[(unsigned char) unsafe[i++]] = 1;
	}

	/* count required memory for the result string */
	for (i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
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
	return result;
}

/* callback for ini parser */
static int ini_callback(void *user, const char *section,
		const char *name, const char *value) {
	typedef struct {
		const char *section;
		const char *name;
		cfg_index index;
	} cfg_line;
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
	const size_t n_lines =
		sizeof(cfg_lines) / sizeof(cfg_lines[0]);
	int i;

	for (i = 0; i < n_lines; i++) {
		if (	!(strcmp(section, cfg_lines[i].section) |
					  strcmp(name,    cfg_lines[i].name)) ) {
			cfg[cfg_lines[i].index] = strdup(value);
		}
	}

	return 1;
}

static inline int get_host_dn(char **dn) {
	char *c, raw_host_name[HOST_NAME_MAX], *host_name = NULL, *filter = NULL;
	int fail, scope, n, result, rc;

	if (!cfg[CFG_HOST_BASE]) {
		pam_syslog(pam, LOG_ERR, "Host LDAP search base not set");
		return PAM_AUTH_ERR;
	}

	fail = gethostname(raw_host_name, HOST_NAME_MAX);
	if (fail) {
		pam_syslog(pam, LOG_ERR, "Unable to determine host name");
		return PAM_AUTH_ERR;
	}

	if ( atoi(cfg[CFG_SHORTEN]) ) {
		/* remove domain parts from hostname */
		for (c = raw_host_name; c < raw_host_name + HOST_NAME_MAX; c++) {
			if (*c == '.') {
				*c = 0;
				break;
			}
		}
		if (debug) pam_syslog(pam, LOG_DEBUG, "Short host name %s", raw_host_name);
	}

	host_name = ldap_escape_filter(host_name);
	rc = asprintf(&filter, cfg[CFG_HOST_FILT], host_name);
	if (rc == -1) {
		filter = NULL;
		result = PAM_AUTH_ERR;
		goto end;
	}
	scope = get_scope(cfg[CFG_HOST_SCOPE]);

	n = get_single_dn(cfg[CFG_HOST_BASE], scope, filter, dn);
	result = (n == 1) ? PAM_SUCCESS : PAM_AUTH_ERR;

end:
	if (filter) free(filter);
	if (host_name) free(host_name);
	return result;
}

static inline LDAP *ldap_connect() {
	int rc;
	struct berval cred;
	const int version3 = LDAP_VERSION3;
	char *binddn;

	rc = ldap_initialize(&ld, cfg[CFG_LDAP_URI]);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Unable to initialize LDAP library: %s",
				strerror(errno));
		return NULL;
	}

	rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version3);
	if (rc != LDAP_OPT_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Unable to request LDAPv3 protocol");
		return NULL;
	}

	binddn =      *(char *) cfg[CFG_LDAP_DN] ? cfg[CFG_LDAP_DN] : NULL;
	cred.bv_val = *(char *) cfg[CFG_LDAP_PW] ? cfg[CFG_LDAP_PW] : NULL;
	cred.bv_len = cred.bv_val ? strlen(cred.bv_val) : 0;

	rc = ldap_sasl_bind_s(ld, binddn, LDAP_SASL_SIMPLE, &cred,
			NULL, NULL, NULL);
	if (rc == LDAP_SUCCESS) {
		return ld;
	} else {
		pam_syslog(pam, LOG_ERR, "Unable to bind to LDAP at %s: %s",
				cfg[CFG_LDAP_URI], ldap_err2string(rc));
		return NULL;
	}
}

/* runs an LDAP query, and returns the DN of a single result;
 * fails if more than one result found (collision);
 * returns number of entries found */
static int get_single_dn(const char *base, int scope, const char *filter, char **dn) {
	int rc, n_items = 0;
	LDAPMessage *res = NULL;
	LDAPMessage *first;

	rc = ldap_search_ext_s(ld, base, scope, filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				filter, ldap_err2string(rc));
		goto end;
	}

	n_items = ldap_count_entries(ld, res);

	switch (n_items) {
		case 0:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"LDAP search '%s' found no entries.", filter);
			}
			*dn = NULL;
			break;
		case 1:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"LDAP search '%s' found 1 entry.", filter);
			}
			first = ldap_first_entry(ld, res);
			*dn = ldap_get_dn(ld, first);
			break;
		default:
			pam_syslog(pam, LOG_WARNING,
					"LDAP search '%s' found %i entries.", filter, n_items);
			*dn = NULL;
	}

end:
	if (res) ldap_msgfree(res);
	return n_items;
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
	for (i = 0; i < sizeof(scopes) / sizeof(scopes[0]); i++) {
		if (strcasecmp(scope_str, scopes[i].kw) == 0)
			return scopes[i].val;
	}
}

/* returns:
 * PAM_SUCCESS if user is super admin;
 * PAM_IGNORE if not;
 * PAM_USER_UNKNOWN if user DN not found;
 * PAM_AUTH_ERR if search failed or collision found */
static inline int authorize_admin(char *raw_dn) {
	int rc, result = PAM_AUTH_ERR, scope;
	LDAPMessage *res = NULL;
	char *dn = NULL, *filter = NULL;

	scope = get_scope(cfg[CFG_ADM_SCOPE]);
	dn = ldap_escape_filter(raw_dn);
	rc = asprintf(&filter, cfg[CFG_ADM_FILT], dn);
	if (rc == -1) {
		filter = NULL;
		result = PAM_AUTH_ERR;
		goto end;
	}

	rc = ldap_search_ext_s(ld, cfg[CFG_ADM_BASE], scope, filter,
			no_attrs, 1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc == LDAP_SUCCESS) {
		if (ldap_count_entries(ld, res)) {
			result = PAM_SUCCESS;
			if (debug) pam_syslog(pam, LOG_DEBUG, "%s is a super admin", raw_dn);
		} else {
			result = PAM_IGNORE;
			if (debug) pam_syslog(pam, LOG_DEBUG, "%s is not a super admin", raw_dn);
		}
	} else {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				filter, ldap_err2string(rc));
	}

end:
	if (res) ldap_msgfree(res);
	free(dn);
	free(filter);
	return result;
}

static inline int get_user_dn(const char *raw_username, char **dn) {
	char *username = NULL, *filter = NULL;
	int scope, result, rc;

	username = ldap_escape_filter(raw_username);
	scope = get_scope(cfg[CFG_USR_SCOPE]);
	rc = asprintf(&filter, cfg[CFG_USR_FILT], username);
	if (rc == -1) {
		filter = NULL;
		result = PAM_AUTH_ERR;
		goto end;
	}

	rc = get_single_dn(cfg[CFG_USR_BASE], scope, filter, dn);
	switch (rc) {
		case 1:
			result = PAM_SUCCESS;
			break;
		case 0:
			pam_syslog(pam, LOG_WARNING, "Unable to find the DN for %s", raw_username);
			result = PAM_USER_UNKNOWN;
			goto end;
		default:
			pam_syslog(pam, LOG_ERR, "Multiple DN found for %s", raw_username);
			result = PAM_AUTH_ERR;
			goto end;
	}
end:
	free(username);
	if (filter) free(filter);
	return result;
}

/* returns:
 * PAM_SUCCESS if user is permitted;
 * PAM_PERM_DENIED if not;
 * PAM_AUTH_ERR if search failed or collision found */
static inline int authorize_user(const char *raw_user_dn, const char *raw_host_dn) {
	int rc, result = PAM_AUTH_ERR, scope;
	LDAPMessage *res;
	char *user_dn, *host_dn, *filter;

	user_dn = ldap_escape_filter(raw_user_dn);
	host_dn = ldap_escape_filter(raw_host_dn);
	rc = asprintf(&filter, cfg[CFG_MEMB_FILT], user_dn, host_dn);
	if (rc == -1) {
		filter = NULL;
		result = PAM_AUTH_ERR;
		goto end;
	}
	scope = get_scope(cfg[CFG_MEMB_SCOPE]);

	rc = ldap_search_ext_s(ld, cfg[CFG_MEMB_BASE], scope, filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc == LDAP_SUCCESS) {
		result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_PERM_DENIED;
	} else {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				filter, ldap_err2string(rc));
	}

end:
	if (res) ldap_msgfree(res);
	if (filter) free(filter);
	free(user_dn);
	free(host_dn);
	return result;
}

/* return true on success */
static inline int read_config() {
	memset((void *) &cfg, 0, sizeof(cfg));
	int fail = ini_parse(CONFIG_FILE, ini_callback, NULL);
	if (fail)
		pam_syslog(pam, LOG_CRIT, "Unable to parse ini file");
	return !fail;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		int argc, const char **argv) {
	const char *user_name;
	char *user_dn = NULL, *host_dn = NULL;
	int result = PAM_AUTH_ERR, rc, i, success;

	pam = pamh;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "debug")) {
			debug = 1;
			break;
		}
	}

	if ( !read_config() ) return PAM_AUTH_ERR;

	/* get user name from PAM */
	rc = pam_get_item(pamh, PAM_USER, (const void **) &user_name);
	if (rc != PAM_SUCCESS
			|| user_name == NULL
			|| *(const char *)user_name == '\0') {
		pam_syslog(pam, LOG_NOTICE, "Cannot obtain the user name");
		return PAM_USER_UNKNOWN;
	}

	/* connect to LDAP */
	ld = ldap_connect();
	if (!ld) return PAM_AUTH_ERR;

	/* get user DN */
	if (get_user_dn(user_name, &user_dn) != PAM_SUCCESS) goto end_ldap;

	/* check if is super admin */
	result = authorize_admin(user_dn);
	if (result != PAM_IGNORE) goto end_ldap;

	result = get_host_dn(&host_dn);
	if (result != PAM_SUCCESS) goto end_ldap;

	/* check if access permitted */
	result = authorize_user(user_dn, host_dn);
	switch (result) {
		case PAM_SUCCESS:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"%s is permitted", user_name);
			}
			break;
		case PAM_PERM_DENIED:
			pam_syslog(pam, LOG_WARNING,
					"%s is not permitted", user_name);
			break;
		case PAM_AUTH_ERR:
			pam_syslog(pam, LOG_ERR,
					"Failed to test if %s is permitted", user_name);
	}

end_ldap:
	ldap_unbind_ext(ld, NULL, NULL);
	if (user_dn) ldap_memfree(user_dn);
	if (host_dn) ldap_memfree(host_dn);

	return result;
}
