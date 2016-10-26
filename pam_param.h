/* Copyright 2016 Development Gateway, Inc
 * This file is part of pam_param, see COPYING */
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

#ifndef CONFIG_FILE
#define CONFIG_FILE "/etc/pam_param.ini"
#endif
