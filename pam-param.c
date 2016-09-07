#define _XOPEN_SOURCE 700

#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <ldap.h>
#include <stdlib.h>

#include "pam-param.h"
#include "inih/ini.h"

config cfg;

static char * ldap_escape_filter(const char *filter) {
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
static int handler(void *user, const char *section, const char *name, const char *value) {
	
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

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int rc;
	char host_name[HOST_NAME_MAX];
	const char **user_name;
	LDAP **ld;

	rc = ini_parse(CONFIG_FILE, handler, NULL);
	if (!rc) return PAM_BUF_ERR;

	/* get user name from PAM */
	rc = pam_get_user(pamh, user_name, NULL);
	if (rc != PAM_SUCCESS) return rc;

	/* connect to LDAP */
	rc = ldap_initialize(ld, cfg.ldap_uri);
	if (rc != LDAP_SUCCESS) return rc;

	rc = ldap_simple_bind_s(ld, cfg.ldap_dn, cfg.ldap_pw);
	if (rc != LDAP_SUCCESS) return rc;

	/* TODO: check if is super admin */

	rc = gethostname(host_name, HOST_NAME_MAX);
	if (rc) return PAM_AUTH_ERR;
	if (cfg.short_name) shorten_name(host_name, HOST_NAME_MAX);

	/* TODO: check if access permitted */

	/* TODO: disconnect from LDAP */
	rc = ldap_unbind(ld);
	if (rc != LDAP_SUCCESS) return rc;

	return PAM_SUCCESS;
}
