#include "pam-param.c"
int main() { 

	int rc;
	char host_name[HOST_NAME_MAX];
	const char **user_name;
	LDAP *ld;
	struct berval cred;

	rc = ini_parse(CONFIG_FILE, handler, NULL);
	if (!rc) return 1;

	/* get user name from PAM */
	rc = pam_get_user(pamh, user_name, NULL);
	if (rc != PAM_SUCCESS) return rc;

	/* connect to LDAP */
	rc = ldap_initialize(&ld, cfg.ldap_uri);
	if (rc != LDAP_SUCCESS) return rc;

	cred.bv_val = cfg.ldap_pw;
	cred.bv_len = strlen(cfg.ldap_pw);
	rc = ldap_sasl_bind_s(ld, cfg.ldap_dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) return rc;

	/* TODO: check if is super admin */

	/*to test escaped use: string = "\\this*is(a)test\0";*/
	rc = gethostname(host_name, HOST_NAME_MAX);
	if (rc) return 5;
	if (cfg.short_name) shorten_name(host_name, HOST_NAME_MAX);

	/* TODO: check if access permitted */

	/*disconnect from LDAP */
	rc = ldap_unbind_ext(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) return rc;

	return 0;
}
