#define _XOPEN_SOURCE 700

#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <ldap.h>
#include <stdlib.h>

#include "pam-param.h"
#include "inih/ini.h"

static int handler(void *user, const char *section, const char *name, const char *value);

config cfg;

static int handler (void *user, const char *section, const char *name, const char *value) {
	
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

/* get host name, optionally chopped at first dot; return 0 on success */
int get_host_name(char *host_name) {
	int rc = gethostname(host_name, HOST_NAME_MAX);
	if (rc) return rc;

	/* TODO: chop */

	return 0;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int rc;
	char host_name[HOST_NAME_MAX];

	rc = ini_parse(CONFIG_FILE, handler, NULL);
	if (!rc) return PAM_BUF_ERR;

	/* TODO: get user name from PAM */

	/* TODO: connect to LDAP */

	/* TODO: check if is super admin */

	rc = get_host_name(host_name);
	if ( !rc ) return PAM_BUF_ERR;

	/* TODO: check if access permitted */

	/* TODO: disconnect from LDAP */

	return PAM_SUCCESS;
}
