#define _XOPEN_SOURCE 700

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
static inline char *get_host_dn(LDAP *ld);
static inline LDAP *ldap_connect();
static int get_single_dn(LDAP *ld, const char *base, int scope, const char *filter, char **dn);
static char *interpolate_filter(const char *filt_templ, ...);
static inline int get_scope(const char *scope_str);
static inline int authorize_admin(LDAP *ld, char *user_dn);
static inline int authorize_user(LDAP *ld, const char *user_dn, const char *host_dn);
static inline int read_config();

char *no_attrs[] = { LDAP_NO_ATTRS, NULL };
int debug = 0;
pam_handle_t *pam = NULL;
char *cfg[10];

/*
 * This function is based on PHP implementation of ldap_escape.
 * See LICENSE-php for copyright info.
 */
static char *ldap_escape_filter(const char *filter) {
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
	static size_t n_lines = sizeof(cfg_lines);
	int i;

	for (i = 0; i < n_lines; i++) {
		if (	!(strcmp(section, cfg_lines[i].section) |
					  strcmp(name,    cfg_lines[i].name)) ) {
			cfg[cfg_lines[i].index] = strdup(value);
		}
	}

	return 1;
}

static inline char *get_host_dn(LDAP *ld) {
	char *dn, *c;
	int fail, n;
	char host_name[HOST_NAME_MAX];

	fail = gethostname(host_name, HOST_NAME_MAX);
	if (fail) return NULL;

	if ( atoi(cfg[CFG_SHORTEN]) ) {
		/* remove domain parts from hostname */
		for (c = host_name; c < host_name + HOST_NAME_MAX; c++) {
			if (*c == '.') {
				*c = 0;
				break;
			}
		}
		if (debug) {
			pam_syslog(pam, LOG_DEBUG,
					"Short host name is %s", host_name);
		}
	}

	char *safe_host_name = ldap_escape_filter(host_name);
	char *filter = interpolate_filter(cfg[CFG_HOST_FILT], host_name);
	int scope = get_scope(cfg[CFG_HOST_SCOPE]);

	get_single_dn(ld, cfg[CFG_HOST_BASE], scope, filter, &dn);

	free(filter);
	free(safe_host_name);
	return dn;
}

static inline LDAP *ldap_connect() {
	int rc;
	LDAP *ld;
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
static int get_single_dn(LDAP *ld, const char *base, int scope, const char *filter, char **dn) {
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

/* printf arguments into LDAP filter */
static char *interpolate_filter(const char *filt_templ, ...) {
	char *result;
	const char *c;
	size_t len;
	va_list ap, ap_original;

	va_start(ap, filt_templ);
	va_copy(ap_original, ap);

	len = strlen(filt_templ);
	for (c = filt_templ; *c; c++) {
		if (*c == '%' && *(c + 1) != '%') { /* not '%%', but format sequence */
			len += strlen(va_arg(ap, char *));
		}
	}

	result = (char *) malloc(++len);
	vsnprintf(result, len, filt_templ, ap_original);
	if (debug) {
		pam_syslog(pam, LOG_DEBUG,
				"Interpolated search filter '%s'", result);
	}

	va_end(ap);
	va_end(ap_original);
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
static inline int authorize_admin(LDAP *ld, char *user_dn) {
	int rc, result = PAM_AUTH_ERR;
	LDAPMessage *res = NULL;
	char *safe_user_dn = ldap_escape_filter(user_dn);
	char *filter = interpolate_filter(cfg[CFG_ADM_FILT], safe_user_dn);
	int scope = get_scope(cfg[CFG_ADM_FILT]);

	rc = ldap_search_ext_s(ld, cfg[CFG_ADM_BASE], scope, filter,
			no_attrs, 1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc == LDAP_SUCCESS) {
		result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_IGNORE;
	} else {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				filter, ldap_err2string(rc));
	}

	if (res) ldap_msgfree(res);
	free(safe_user_dn);
	free(filter);
	return result;
}

/* returns:
 * PAM_SUCCESS if user is permitted;
 * PAM_PERM_DENIED if not;
 * PAM_AUTH_ERR if search failed or collision found */
static inline int authorize_user(LDAP *ld,
		const char *user_dn, const char *host_dn) {
	int rc, result = PAM_AUTH_ERR;
	LDAPMessage *res;

	char *safe_user_dn = ldap_escape_filter(user_dn);
	char *safe_host_dn = ldap_escape_filter(host_dn);
	char *filter = interpolate_filter(cfg[CFG_MEMB_FILT],
			safe_user_dn, safe_host_dn);
	int scope = get_scope(cfg[CFG_MEMB_SCOPE]);

	rc = ldap_search_ext_s(ld, cfg[CFG_MEMB_BASE], scope, filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc == LDAP_SUCCESS) {
		result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_PERM_DENIED;
	} else {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				filter, ldap_err2string(rc));
	}

	if (res) ldap_msgfree(res);
	free(safe_user_dn);
	free(safe_host_dn);
	free(filter);
	return result;
}

/* return true on success */
inline int read_config() {
	memset((void *) &cfg, 0, sizeof(cfg));
	int fail = ini_parse(CONFIG_FILE, ini_callback, NULL);
	if (fail)
		pam_syslog(pam, LOG_CRIT, "Unable to parse ini file");
	return !fail;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		int argc, const char **argv) {
	const char *user_name;
	char *user_dn, *host_dn;
	LDAP *ld;
	int result = PAM_AUTH_ERR, rc, i, success;

	pam = pamh;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "debug")) {
			debug = 1;
			break;
		}
	}

	if (!read_config) return PAM_AUTH_ERR;

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
	char *safe_user_name = ldap_escape_filter(user_name);
	char *user_filter = interpolate_filter(cfg[CFG_USR_FILT], user_name);
	int user_scope = get_scope(cfg[CFG_USR_SCOPE]);
	rc = get_single_dn(ld, cfg[CFG_USR_BASE], user_scope, user_filter, &user_dn);
	switch (rc) {
		case 1:
			break;
		case 0:
			pam_syslog(pam, LOG_WARNING, "Unable to find the DN for %s", user_name);
			result = PAM_USER_UNKNOWN;
			goto end_ldap;
		default:
			pam_syslog(pam, LOG_ERR, "Multiple DN found for %s", user_name);
			result = PAM_AUTH_ERR;
			goto end_ldap;
	}

	/* check if is super admin */
	result = authorize_admin(ld, user_dn);
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

	host_dn = get_host_dn(ld);
	if (!host_dn) {
		pam_syslog(pam, LOG_ERR, "Unable to determine host name");
		result = PAM_AUTH_ERR;
		goto end_ldap;
	}

	/* check if access permitted */
	result = authorize_user(ld, user_dn, host_dn);
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
	free(user_filter);
	free(safe_user_name);

	return result;
}
