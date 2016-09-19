#include <pam_modules.h>

#define PAM_SM_ACCOUNT
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);

/* stubs: in case the admin mistakenly calls the module */
#define NOT_IMPLEMENTED(f) \
PAM_EXTERN int f(pam_handle_t *pamh, int flags) { \
	return PAM_SERVICE_ERR; \
}

#define PAM_SM_AUTH
NOT_IMPLEMENTED(pam_authenticate)

#define PAM_SM_PASSWORD
NOT_IMPLEMENTED(pam_chauthtok)

#define PAM_SM_SESSION
NOT_IMPLEMENTED(pam_open_session)
NOT_IMPLEMENTED(pam_close_session)

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

int handler(void *user, const char *section, const char *name, const char *value);
void shorten_name(char *host_name, int len);
