#include "pam-param.c"

int main() { 

	int rc;
	char host_name[HOST_NAME_MAX];

	rc = ini_parse(CONFIG_FILE, handler, NULL);
	if (rc) return 1;

	/* TODO: get user name from PAM */

	/* TODO: connect to LDAP */

	/* TODO: check if is super admin */

	rc = gethostname(host_name, HOST_NAME_MAX);
	if (rc) return 5;
	if (cfg.short_name) shorten_name(host_name, HOST_NAME_MAX);

	return 0;

	/* TODO: check if access permitted */

	/* TODO: disconnect from LDAP */


}
