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

#include "pam_param.h"
#include "inih/ini.h"

config cfg;
char *no_attrs[] = { LDAP_NO_ATTRS, NULL };
int debug = 0;
pam_handle_t *pam = NULL;

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
	#define SECTION(s) strcmp(s,section) == 0
	#define NAME(n) strcmp(n,name) == 0

	if (SECTION("")) {
		if (NAME("short_name")) cfg.short_name = atoi(value);
	} else if (SECTION("ldap")) {
		if (NAME("uri")) {
			cfg.ldap_uri = strdup(value);
		} else if (NAME("binddn")) {
			cfg.ldap_dn = ( *(char *) value == 0 ) ?  NULL : strdup(value);
		} else if (NAME("bindpw")) {
			cfg.ldap_pw = ( *(char *) value == 0 ) ?  NULL : strdup(value);
		} else {
			return 0;
		}
	} else {
		ldap_query *q;

		if (SECTION("admin")) {
			q = &(cfg.admin);
		} else if (SECTION("user")) {
			q = &(cfg.user);
		} else if (SECTION("host")) {
			q = &(cfg.host);
		} else if (SECTION("membership")) {
			q = &(cfg.membership);
		} else {
			return 0;
		}

		if (NAME("base")) {
			q->base = strdup(value);
		} else if (NAME("scope")) {
			q->scope = atoi(value);
		} else if (NAME("filter")) {
			q->filter = strdup(value);
		} else {
			return 0;
		}
	}
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
int get_single_dn(LDAP *ld, ldap_query q, char **dn) {
	int rc, n_items = 0;
	LDAPMessage *res = NULL;
	LDAPMessage *first;

	rc = ldap_search_ext_s(ld, q.base, q.scope, q.filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				q.filter, ldap_err2string(rc));
		goto end;
	}

	n_items = ldap_count_entries(ld, res);

	switch (n_items) {
		case 0:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"LDAP search '%s' found no entries.", q.filter);
			}
			break;
		case 1:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"LDAP search '%s' found 1 entry.", q.filter);
			}
			first = ldap_first_entry(ld, res);
			*dn = ldap_get_dn(ld, first);
			break;
		default:
			pam_syslog(pam, LOG_WARNING,
					"LDAP search '%s' found %i entries.", q.filter, n_items);
	}

end:
	if (res) ldap_msgfree(res);
	return n_items;
}

/* printf arguments into LDAP filter */
void interpolate_filter(ldap_query *q, const char *a, const char *b) {
	char *filter;
	size_t len;

	len = strlen(q->filter);

	if (a) len += strlen(a);
	if (b) len += strlen(b);

	filter = (char *) malloc(++len);
	snprintf(filter, len, q->filter, a, b);
	free(q->filter);
	q->filter = filter;
	if (debug) {
		pam_syslog(pam, LOG_DEBUG,
				"Interpolated search filter '%s'", q->filter);
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

	interpolate_filter(&cfg.admin, user_dn, NULL);

	rc = ldap_search_ext_s(ld, cfg.admin.base, cfg.admin.scope, cfg.admin.filter,
			no_attrs, 1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				cfg.admin.filter, ldap_err2string(rc));
		goto end;
	}

	result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_IGNORE;

end:
	if (user_dn) ldap_memfree(user_dn);
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

	rc = get_single_dn(ld, cfg.host, &host_dn);
	if (rc != 1) {
		result = PAM_AUTH_ERR;
		goto end;
	}

	interpolate_filter(&cfg.membership, user_dn, host_dn);

	rc = ldap_search_ext_s(ld, cfg.membership.base, cfg.membership.scope, cfg.membership.filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "LDAP search '%s' failed: %s",
				cfg.membership.filter, ldap_err2string(rc));
		goto end;
	}

	result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_PERM_DENIED;

end:
	if (user_dn) ldap_memfree(user_dn);
	if (host_dn) ldap_memfree(host_dn);
	return result;
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

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "debug")) {
			debug = 1;
			break;
		}
	}

	rc = ini_parse(CONFIG_FILE, handler, NULL);
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
	rc = ldap_initialize(&ld, cfg.ldap_uri);
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

	cred.bv_val = cfg.ldap_pw;
	cred.bv_len = cfg.ldap_pw ? strlen(cfg.ldap_pw) : 0;

	rc = ldap_sasl_bind_s(ld, cfg.ldap_dn, LDAP_SASL_SIMPLE, &cred,
			NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		pam_syslog(pam, LOG_ERR, "Unable to bind to LDAP at %s: %s",
				cfg.ldap_uri, ldap_err2string(rc));
		return PAM_AUTH_ERR;
	}

	interpolate_filter(&cfg.user, user_name, NULL);
	rc = get_single_dn(ld, cfg.user, &user_dn);
	if (rc != 1) {
		if (rc) {
			pam_syslog(pam, LOG_ERR, "Multiple DN found for %s", cfg.user);
			result = PAM_AUTH_ERR;
		} else {
			pam_syslog(pam, LOG_WARNING, "Unable to find the DN for %s", cfg.user);
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
						"%s is a super admin", cfg.user);
			}
			goto end_ldap;
		case PAM_AUTH_ERR:
			pam_syslog(pam, LOG_ERR,
					"Failed to test if %s is a super admin", cfg.user);
			goto end_ldap;
	}

	/* get host name */
	rc = gethostname(host_name, HOST_NAME_MAX);
	if (rc) {
		pam_syslog(pam, LOG_ERR, "Unable to determine host name");
		result = PAM_AUTH_ERR;
		goto end_ldap;
	}

	if (cfg.short_name) {
		shorten_name(host_name, HOST_NAME_MAX);
		if (debug) {
			pam_syslog(pam, LOG_DEBUG,
					"Short host name is %s", host_name);
		}
	}

	interpolate_filter(&cfg.host, host_name, NULL);

	/* check if access permitted */
	result = user_permitted(ld, user_dn);

	switch (result) {
		case PAM_SUCCESS:
			if (debug) {
				pam_syslog(pam, LOG_DEBUG,
						"%s is permitted on %s", cfg.user, host_name);
			}
			break;
		case PAM_PERM_DENIED:
			pam_syslog(pam, LOG_WARNING,
					"%s is not permitted on %s", cfg.user, host_name);
			break;
		case PAM_AUTH_ERR:
			pam_syslog(pam, LOG_ERR,
					"Failed to test if %s is permitted on %s", cfg.user, host_name);
	}

end_ldap:
	ldap_unbind_ext(ld, NULL, NULL);
	return result;
}
