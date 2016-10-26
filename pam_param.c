#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <ldap.h>
#include <lber.h>
#include <syslog.h>
#include <pam_ext.h>
#include <errno.h>
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

static char *ldap_escape_filter(const char *);
static int ini_callback(void *, const char *, const char *, const char *);
static int search_dn(const char *, int, const char *, char **);
static inline LDAP *ldap_connect();
static inline int get_host_dn(char **);
static inline int get_user_dn(const char *, char **);
static inline int get_scope(const char *);
static inline int authorize_admin(char *);
static inline int authorize_user(const char *, const char *);
static inline int read_config();

char *no_attrs[] = { LDAP_NO_ATTRS, NULL };
int debug = 0;
pam_handle_t *pam = NULL;
LDAP *ld = NULL;
cfg_line cfg_lines[] = {
	{"",           "short_name", CFG_SHORTEN},
	{"ldap",       "uri",        CFG_LDAP_URI},
	{"ldap",       "binddn",     CFG_LDAP_DN},
	{"ldap",       "bindpw",     CFG_LDAP_PW},
	{"admin",      "base",       CFG_ADM_BASE},
	{"admin",      "scope",      CFG_ADM_SCOPE},
	{"admin",      "filter",     CFG_ADM_FILT},
	{"user",       "base",       CFG_USR_BASE},
	{"user",       "scope",      CFG_USR_SCOPE},
	{"user",       "filter",     CFG_USR_FILT},
	{"host",       "base",       CFG_HOST_BASE},
	{"host",       "scope",      CFG_HOST_SCOPE},
	{"host",       "filter",     CFG_HOST_FILT},
	{"membership", "base",       CFG_MEMB_BASE},
	{"membership", "scope",      CFG_MEMB_SCOPE},
	{"membership", "filter",     CFG_MEMB_FILT},
};
char *cfg[sizeof(cfg_lines) / sizeof(cfg_lines[0])] = { NULL };

/* Main library function: account management.
Args, returns: see pam_sm_acct_mgmt(3) */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
	const char *username;
	char *user_dn = NULL, *host_dn = NULL;
	int result = PAM_SERVICE_ERR, rc, i, success;

	pam = pamh;

	/* read module arguments */
	switch (argc) {
		case 0:
			break;

		case 1:
			if (!strcmp(argv[0], "debug")) {
				debug = 1;
				break;
			}

		default:
			pam_syslog(pam, LOG_CRIT, "Invalid arguments");
			return PAM_SERVICE_ERR;
	}

	if ( !read_config() ) return PAM_SERVICE_ERR;

	/* get user name from PAM */
	rc = pam_get_item(pamh, PAM_USER, (const void **) &username);
	if (rc != PAM_SUCCESS || username == NULL || *(const char *)username == '\0') {
		pam_syslog(pam, LOG_NOTICE, "Cannot obtain the user name");
		return PAM_USER_UNKNOWN;
	}

	/* connect to LDAP */
	ld = ldap_connect();
	if (!ld) return PAM_AUTH_ERR;

	/* get user DN */
	result = get_user_dn(username, &user_dn);
	if (result != PAM_SUCCESS) goto end;

	/* check if is super admin */
	result = authorize_admin(user_dn);
	if (result != PAM_IGNORE) goto end;

	result = get_host_dn(&host_dn);
	if (result != PAM_SUCCESS) goto end;

	/* check if access permitted */
	result = authorize_user(user_dn, host_dn);

end:
	ldap_unbind_ext(ld, NULL, NULL);
	if (user_dn) ldap_memfree(user_dn);
	if (host_dn) ldap_memfree(host_dn);

	return result;
}

/* Read INI config.
Returns: non-zero on success */
static inline int read_config() {
	int fail, i;
	const size_t cfg_size = sizeof(cfg) / sizeof(cfg[0]);

	fail = ini_parse(CONFIG_FILE, ini_callback, NULL);
	if (fail) {
		pam_syslog(pam, LOG_CRIT, "Unable to parse ini file");
		goto end;
	}

	/* check for unset settings */
	for (i = 0; i < cfg_size; i++) {
		if ( !cfg[cfg_lines[i].index] ) {
			pam_syslog(pam, LOG_CRIT,
					CONFIG_FILE ": missing setting '%s' in section '%s'",
					cfg_lines[i].name, cfg_lines[i].section);
			return 1;
		}
	}

end:
	return !fail;
}

/* Connect and bind to LDAP.
Returns: LDAP handle or NULL */
static inline LDAP *ldap_connect() {
	int rc;
	struct berval cred;
	const int version3 = LDAP_VERSION3;
	char *binddn;

	/* allocate LDAP structure */
	rc = ldap_initialize(&ld, cfg[CFG_LDAP_URI]);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Unable to initialize LDAP library: %s",
				strerror(errno));
		return NULL;
	}

	/* request LDAPv3 */
	rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version3);
	if (rc != LDAP_OPT_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Unable to request LDAPv3 protocol");
		return NULL;
	}

	binddn =      *(char *) cfg[CFG_LDAP_DN] ? cfg[CFG_LDAP_DN] : NULL;
	cred.bv_val = *(char *) cfg[CFG_LDAP_PW] ? cfg[CFG_LDAP_PW] : NULL;
	cred.bv_len = cred.bv_val ? strlen(cred.bv_val) : 0;

	/* connect to LDAP server and bind */
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

/* Determine LDAP DN from username.
Args:
	raw_username - username as provided by PAM, must be escaped
	dn - receives DN if found
Returns:
	PAM_BUF_ERR - can't allocate memory
	PAM_SUCCESS - found one user
	PAM_USER_UNKNOWN - found no users
	PAM_AUTH_ERR - multiple matching users found */
static inline int get_user_dn(const char *raw_username, char **dn) {
	char *username = NULL, *filter = NULL;
	int scope, result, n;

	/* prepare LDAP search: scope & filter */
	username = ldap_escape_filter(raw_username);
	if (!username) return PAM_BUF_ERR;

	scope = get_scope(cfg[CFG_USR_SCOPE]);

	n = asprintf(&filter, cfg[CFG_USR_FILT], username);
	if (n == -1) {
		filter = NULL;
		result = PAM_BUF_ERR;
		goto end;
	}

	/* run LDAP search */
	n = search_dn(cfg[CFG_USR_BASE], scope, filter, dn);
	switch (n) {
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

/* Determine LDAP DN from hostname.
Args:
	dn - receives DN if found
Returns:
	PAM_BUF_ERR - can't allocate memory
	PAM_SERVICE_ERR - can't determine hostname
	PAM_SUCCESS - found one user
	PAM_USER_UNKNOWN - found no users
	PAM_AUTH_ERR - multiple matching users found */
static inline int get_host_dn(char **dn) {
	char *c, raw_hostname[HOST_NAME_MAX], *hostname = NULL, *filter = NULL;
	int scope, n, result;

	if ( gethostname(raw_hostname, HOST_NAME_MAX) ) {
		pam_syslog(pam, LOG_ERR, "Unable to determine hostname");
		return PAM_SERVICE_ERR;
	}

	/* remove domain if FQDN */
	if ( atoi(cfg[CFG_SHORTEN]) ) {
		for (c = raw_hostname; c < raw_hostname + HOST_NAME_MAX; c++) {
			if (*c == '.') {
				*c = 0;
				break;
			}
		}
		if (debug) pam_syslog(pam, LOG_DEBUG, "Short host name %s", raw_hostname);
	}

	/* prepare LDAP search: scope & filter */
	hostname = ldap_escape_filter(raw_hostname);
	if (!hostname) return PAM_BUF_ERR;

	scope = get_scope(cfg[CFG_HOST_SCOPE]);

	n = asprintf(&filter, cfg[CFG_HOST_FILT], hostname);
	if (n == -1) {
		filter = NULL;
		result = PAM_BUF_ERR;
		goto end;
	}

	/* run LDAP search */
	n = search_dn(cfg[CFG_HOST_BASE], scope, filter, dn);
	switch (n) {
		case 1:
			result = PAM_SUCCESS;
			break;
		case 0:
			pam_syslog(pam, LOG_WARNING, "Unable to find the DN for %s", raw_hostname);
			result = PAM_AUTH_ERR;
			goto end;
		default:
			pam_syslog(pam, LOG_ERR, "Multiple DN found for %s", raw_hostname);
			result = PAM_AUTH_ERR;
			goto end;
	}

end:
	free(hostname);
	if (filter) free(filter);
	return result;
}

/* Check if the user is a member of super admins group in LDAP.
Args:
	raw_dn - user DN, must be escaped
Returns:
	PAM_BUF_ERR - can't allocate memory
	PAM_SUCCESS - user is super admin
	PAM_IGNORE - user is not super admin, module must continue
	PAM_USER_UNKNOWN - user DN not found;
	PAM_AUTH_ERR - search failed or multiple users found */
static inline int authorize_admin(char *raw_dn) {
	int n, rc, result = PAM_AUTH_ERR, scope;
	char *dn = NULL, *filter = NULL;

	/* prepare LDAP search: scope & filter */
	dn = ldap_escape_filter(raw_dn);
	if (!dn) return PAM_BUF_ERR;

	scope = get_scope(cfg[CFG_ADM_SCOPE]);

	n = asprintf(&filter, cfg[CFG_ADM_FILT], dn);
	if (n == -1) {
		filter = NULL;
		result = PAM_BUF_ERR;
		goto end;
	}

	/* run LDAP search */
	n = search_dn(cfg[CFG_ADM_BASE], scope, filter, NULL);
	switch (n) {
		case 0:
			result = PAM_IGNORE;
			if (debug) pam_syslog(pam, LOG_DEBUG, "%s is not a super admin", raw_dn);
			break;
		default:
			result = PAM_SUCCESS;
			if (debug) pam_syslog(pam, LOG_DEBUG, "%s is a super admin", raw_dn);
	}

end:
	free(dn);
	if (filter) free(filter);
	return result;
}

/* Check if the user and the host both belong to any object.
Args:
	raw_user_dn, raw_host_dn - DNs, must be escaped
Returns:
	PAM_BUF_ERR - can't allocate memory
	PAM_SUCCESS - user is permitted
	PAM_PERM_DENIED - user is not permitted */
static inline int authorize_user(const char *raw_user_dn, const char *raw_host_dn) {
	int n, rc, result = PAM_AUTH_ERR, scope;
	LDAPMessage *res;
	char *user_dn = NULL, *host_dn = NULL, *filter = NULL;

	/* prepare LDAP search: scope & filter */
	user_dn = ldap_escape_filter(raw_user_dn);
	if (!user_dn) return PAM_BUF_ERR;

	host_dn = ldap_escape_filter(raw_host_dn);
	if (!host_dn) {
		free(user_dn);
		return PAM_BUF_ERR;
	}

	scope = get_scope(cfg[CFG_MEMB_SCOPE]);

	rc = asprintf(&filter, cfg[CFG_MEMB_FILT], user_dn, host_dn);
	if (rc == -1) {
		filter = NULL;
		result = PAM_BUF_ERR;
		goto end;
	}

	/* run LDAP search */
	n = search_dn(cfg[CFG_MEMB_BASE], scope, filter, NULL);
	switch (n) {
		case 0:
			result = PAM_PERM_DENIED;
			if (debug) pam_syslog(pam, LOG_WARNING, "%s is not permitted", raw_user_dn);
			break;
		default:
			result = PAM_SUCCESS;
			if (debug) pam_syslog(pam, LOG_DEBUG, "%s is permitted", raw_user_dn);
	}

end:
	if (filter) free(filter);
	free(user_dn);
	free(host_dn);
	return result;
}

/* Escape a string to be used in search filter.
Args:
	string - string to escape
Returns:
	escaped string or NULL
Copyright:
	This function is based on PHP implementation of ldap_escape, see LICENSE-php  */
static char *ldap_escape_filter(const char *string) {
	char map[256] = { 0 };
	const char unsafe[] = "\\*()\0";
	const char hex[] = "0123456789abcdef";
	char *result;
	int i = 0, p = 0;
	size_t len = 1;

	if (!string) return NULL;

	/* map unsafe character */
	for (i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
		map[(unsigned char) unsafe[i]] = 1;
	}

	/* count required memory for the result string */
	for (i = 0; i < strlen(string); i++) {
		len += (map[(unsigned char) string[i]]) ? 3 : 1;
	}

	result = (char *) malloc(len);
	if (!result) return NULL;

	for (i = 0; i < strlen(string); i++) {
		unsigned char v = (unsigned char) string[i];

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

/* Callback for ini parser,
Args, returns: see ini.h */
static int ini_callback(void *user, const char *section, const char *name, const char *value) {
	int i, name_match, section_match;
	const size_t cfg_size = sizeof(cfg) / sizeof(cfg[0]);

	for (i = 0; i < cfg_size; i++) {
		name_match =    !strcmp(name,    cfg_lines[i].name);
		section_match = !strcmp(section, cfg_lines[i].section);
		if (name_match && section_match) cfg[cfg_lines[i].index] = strdup(value);
	}

	return 1;
}

/* Run an LDAP query, and return the DN of a single result.
Args:
	base, scope, filter - LDAP search parameters
	dn - if not NULL, receives the single DN found, otherwise unchanged
Returns: number of entries found */
static int search_dn(const char *base, int scope, const char *filter, char **dn) {
	int rc, n = 0;
	LDAPMessage *res = NULL;

	rc = ldap_search_ext_s(ld, base, scope, filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Search '%s' failed: %s", filter, ldap_err2string(rc));
		goto end;
	}

	n = ldap_count_entries(ld, res);

	switch (n) {
		case 0:
			if (debug) pam_syslog(pam, LOG_DEBUG, "Search '%s': no entries", filter);
			break;
		case 1:
			if (debug) pam_syslog(pam, LOG_DEBUG, "Search '%s': 1 entry", filter);
			if (dn) *dn = ldap_get_dn(ld, ldap_first_entry(ld, res));
			break;
		default:
			pam_syslog(pam, LOG_WARNING, "Search '%s': %i entries", filter, n);
	}

end:
	if (res) ldap_msgfree(res);
	return n;
}

/* Convert scope keyword string to numeric value.
Args:
	scope_str - scope keyword
Returns:
	numeric scope for LDAP library */
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
	const int n_scopes = sizeof(scopes) / sizeof(scopes[0]);
	int i;

	for (i = 0; i < n_scopes; i++) {
		if (strcasecmp(scope_str, scopes[i].kw) == 0) return scopes[i].val;
	}
}
