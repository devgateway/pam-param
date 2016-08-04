#define PAM_SM_ACCOUNT
#define _XOPEN_SOURCE 700

#include <pam_modules.h>
#include <unistd.h>
#include <limits.h>

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv);
