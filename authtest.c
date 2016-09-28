#include <stdio.h>
#include <stdlib.h>
#include <pam_appl.h>

#ifndef SERVICE_NAME
#define SERVICE_NAME "pam_param_test"
#endif

int try_acct(const char *username) {
	int rc, auth_code;
	struct pam_conv conv;
	pam_handle_t *pamh;

	rc = pam_start(SERVICE_NAME, username, &conv, &pamh);
	if (rc != PAM_SUCCESS) goto fail;

	auth_code = pam_acct_mgmt(pamh, 0);
	fprintf(stderr, "%s\n", pam_strerror(pamh, auth_code));

	rc = pam_end(pamh, rc);
	if (rc == PAM_SUCCESS) return auth_code;

fail:
	fprintf(stderr, "PAM stack failed: %s\n", pam_strerror(pamh, rc));
	return rc;
}

int main(int argc, const char *argv[]) {
	char username[32 + 1];

	switch (argc) {
		case 1: /* interactive */
			for (;;) {
				printf("Enter user name: ");
				if ( scanf("%32s", &username) != 1 ) return 0;
				try_acct(username);
			}

		case 2: /* non-interactive */
			return try_acct(argv[1]);

		default:
			fprintf(stderr, "Usage: %s [USERNAME]\n", argv[0]);
			return -1;
	}
}
