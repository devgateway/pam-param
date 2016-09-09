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

/* handler for ini parser */
int handler(void *user, const char *section, const char *name, const char *value) {

	#define SECTION(s) strcmp(s,section)==0
	#define NAME(n) strcmp(n,name)==0

	if (SECTION("")) {
		if (NAME("short_name")) {
			cfg.short_name = atoi(value);
		}
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

/* return object count or LDAP_FAIL */
int count_entries(LDAP *ld, const ldap_query *query) {
}

/* get short hostname */
void shorten_name(char *host_name, int len) {
	char *c;
	for (c = host_name; c < host_name + len; c++) {
		switch (*c) {
			case '.':	*c = 0;
			case 0:	  return;
		}
	}
}

int get_dn(LDAP *ld, ldap_query q, char *dn) {

	int rc;
	LDAPMessage *res;
	LDAPMessage *ent;

	rc = ldap_search_ext_s(ld, q.base, q.scope, q.filter, LDAP_NO_ATTRS, 1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    if (ldap_count_entries != 1) return LDAP_INAPPROPRIATE_AUTH;
	ent = ldap_first_entry(ld,res);
	dn = ldap_get_dn(ld, ent);

	free(res);
    return 0;
}

void complete_ldap_query (ldap_query q, char *str) {
    char *res;
    size_t full_length;
    full_len = strlen(q.filter) - 2 + strlen(str) + 1;
    res = (char *)malloc(full_len * sizeof(char));
    snprintf(res, full_len, q.filter, add);
    free(q.filter);
    q.filter = res;
}

/*returns 1 if user is super admin*/
int is_super_admin (LDAP *ld) {
    char *user_dn;
    int rc;
    ldap_query q = cfg.user;

    rc = get_dn(ld, q, user_dn);
    if (rc !=0 ) return rc;
    complete_ldap_query (q, user_dn);

	rc = ldap_search_ext_s(ld, q.base, q.scope, q.filter, LDAP_NO_ATTRS, 1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
    if (ldap_count_entries != 1) return LDAP_INAPPROPRIATE_AUTH;

    ldap_mem_free(user_dn);
    return 1;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int rc;
	char host_name[HOST_NAME_MAX];
	const char **user_name;
	LDAP *ld;

	rc = ini_parse(CONFIG_FILE, handler, NULL);
	if (rc) return PAM_AUTH_ERR;

	/* get user name from PAM */
	rc = pam_get_user(pamh, user_name, NULL);
	if (rc != PAM_SUCCESS) return rc;
    complete_ldap_query(cfg.user,&user_name);

	/* connect to LDAP */
	rc = ldap_initialize(&ld, cfg.ldap_uri);
	if (rc != LDAP_SUCCESS) return rc;

	struct berval cred;
	cred.bv_val = cfg.ldap_pw;
	cred.bv_len = strlen(cfg.ldap_pw);

	rc = ldap_sasl_bind_s(ld, cfg.ldap_dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) return rc;

	/* check if is super admin */
    if (is_super_admin(ld)) return PAM_SUCCESS;

    /* get hostname from pam*/
	rc = gethostname(host_name, HOST_NAME_MAX);
	if (rc) return PAM_AUTH_ERR;
	if (cfg.short_name) shorten_name(host_name, HOST_NAME_MAX);
    complete_ldap_query(cfg.host,host_name);

	/* TODO: check if access permitted */

	/* disconnect from LDAP */
	rc = ldap_unbind_ext(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) return rc;

	return PAM_SUCCESS;
}
