#include <pam_modules.h>

#define PAM_SM_ACCOUNT
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);

typedef struct {
	char *base;
	int scope;
	char *filter;
} ldap_query;

typedef struct {
	int short_name;
	const char *ldap_uri;
	const char *ldap_dn;
	char *ldap_pw;
	ldap_query admin;
	ldap_query user;
	ldap_query host;
	ldap_query membership;
} config;

#ifndef CONFIG_FILE
#define CONFIG_FILE "/etc/pam_param.ini"
#endif

#define LDAP_FAIL -1
