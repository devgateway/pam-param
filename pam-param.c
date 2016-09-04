#define _XOPEN_SOURCE 700

#include <unistd.h>
#include <limits.h>

#include "pam-param.h"
#include "inih/ini.h"

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	char hostname[HOST_NAME_MAX];
	int rc;

	rc = gethostname(hostname, HOST_NAME_MAX);
	if (rc) return PAM_BUF_ERR;

	return PAM_SUCCESS;
}
