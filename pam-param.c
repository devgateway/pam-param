#define _XOPEN_SOURCE 700

#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <ldap.h>

#include "pam-param.h"
#include "inih/ini.h"

/* returns NULL on failure */
config *config_read(const char *filename) {
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

	config *cfg = config_read(CONFIG_FILE);
	if (!cfg) return PAM_BUF_ERR;

	/* TODO: get user name from PAM */

	/* TODO: connect to LDAP */

	/* TODO: check if is super admin */

	rc = get_host_name(host_name);
	if ( !rc ) return PAM_BUF_ERR;

	/* TODO: check if access permitted */

	/* TODO: disconnect from LDAP */

	return PAM_SUCCESS;
}
