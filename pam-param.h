#define PAM_SM_ACCOUNT

#include <pam_modules.h>

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);
