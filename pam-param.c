#define _XOPEN_SOURCE 700

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ldap.h>
#include <lber.h>

#include "pam-param.h"
#include "inih/ini.h"


config cfg;
char *no_attrs[] = { LDAP_NO_ATTRS, NULL };

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
int handler(void *user, const char *section, const char *name, const char *value) {
	#define SECTION(s) strcmp(s,section) == 0
	#define NAME(n) strcmp(n,name) == 0

	if (SECTION("")) {
		if (NAME("short_name")) cfg.short_name = atoi(value);
	} else if (SECTION("ldap")) {
		if (NAME("uri")) {
			cfg.ldap_uri = strdup(value);
		} else if (NAME("binddn")) {
			cfg.ldap_dn = strdup(value);
		} else if (NAME("bindpw")) {
			cfg.ldap_pw = strdup(value);
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
	if (rc != LDAP_SUCCESS) goto end;

	n_items = ldap_count_entries(ld, res);

	if (n_items == 1) {
		first = ldap_first_entry(ld, res);
		*dn = ldap_get_dn(ld, first);
	}

end:
	if (res) ldap_msgfree(res);
	return n_items;
}

/* printf arguments into LDAP filter */
void interpolate_filter(ldap_query q, const char *a, const char *b) {
	char *filter;
	size_t len;

	len = strlen(q.filter);

	if (a) len += strlen(a);
	if (b) len += strlen(b);

	filter = (char *) malloc(++len);
	snprintf(filter, len, q.filter, a, b);
	free(q.filter);
	q.filter = filter;
}

/* returns:
 * PAM_SUCCESS if user is super admin;
 * PAM_IGNORE if not;
 * PAM_USER_UNKNOWN if user DN not found;
 * PAM_AUTH_ERR if search failed or collision found */
int is_super_admin(LDAP *ld) {
	char *user_dn = NULL;
	int rc, result = PAM_AUTH_ERR;
	ldap_query q = cfg.admin;
	LDAPMessage *res = NULL;

	rc = get_single_dn(ld, cfg.user, &user_dn);
	if (rc != 1) {
		result = rc ? PAM_AUTH_ERR : PAM_USER_UNKNOWN;
		goto end;
	}

	interpolate_filter(q, user_dn, NULL);

	rc = ldap_search_ext_s(ld, q.base, q.scope, q.filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) goto end;

	result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_PERM_DENIED;

end:
	if (user_dn) ldap_memfree(user_dn);
	if (res) ldap_msgfree(res);
	return result;
}

/* returns:
 * PAM_SUCCESS if user is permitted;
 * PAM_PERM_DENIED if not;
 * PAM_USER_UNKNOWN if user DN not found;
 * PAM_AUTH_ERR if search failed or collision found */
int user_permitted(LDAP *ld) {
	char *user_dn = NULL, *host_dn = NULL;
	int rc, count, result = PAM_AUTH_ERR;
	ldap_query q = cfg.membership;
	LDAPMessage *res;

	rc = get_single_dn(ld, cfg.user, &user_dn);
	if (rc != 1) {
		result = rc ? PAM_AUTH_ERR : PAM_USER_UNKNOWN;
		goto end;
	}

	rc = get_single_dn(ld, cfg.host, host_dn);
	if (rc != 1) {
		result = PAM_AUTH_ERR;
		goto end;
	}

	interpolate_filter(q, user_dn, host_dn);

	rc = ldap_search_ext_s(ld, q.base, q.scope, q.filter, no_attrs,
			1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (rc != LDAP_SUCCESS) goto end;

	result = ldap_count_entries(ld, res) ? PAM_SUCCESS : PAM_IGNORE;

end:
	if (user_dn) ldap_memfree(user_dn);
	if (host_dn) ldap_memfree(host_dn);
	return result;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int rc;
	char host_name[HOST_NAME_MAX];
	const char **user_name;
	LDAP *ld;
	struct berval cred;
	int result = PAM_AUTH_ERR;

	rc = ini_parse(CONFIG_FILE, handler, NULL);
	if (rc) return PAM_AUTH_ERR;

	/* get user name from PAM */
	rc = pam_get_user(pamh, user_name, NULL);
	if (rc != PAM_SUCCESS) return PAM_AUTH_ERR;

	/* connect to LDAP */
	rc = ldap_initialize(&ld, cfg.ldap_uri);
	if (rc != LDAP_SUCCESS) return PAM_AUTH_ERR;

	cred.bv_val = cfg.ldap_pw;
	cred.bv_len = strlen(cfg.ldap_pw);

	rc = ldap_sasl_bind_s(ld, cfg.ldap_dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) return PAM_AUTH_ERR;

	interpolate_filter(cfg.user, *user_name, NULL);

	/* check if is super admin */
	result = is_super_admin(ld);
	switch (result) {
		case PAM_SUCCESS:
			goto end_ldap;
		case PAM_USER_UNKNOWN:
		case PAM_AUTH_ERR:
			goto end_ldap;
	}

	/* get host name */
	rc = gethostname(host_name, HOST_NAME_MAX);
	if (rc) {
		result = PAM_AUTH_ERR;
		goto end_ldap;
	}

	if (cfg.short_name) shorten_name(host_name, HOST_NAME_MAX);

	interpolate_filter(cfg.host, host_name, NULL);

	/* check if access permitted */
	result = user_permitted(ld);

end_ldap:
	ldap_unbind_ext(ld, NULL, NULL);
	return result;
}
