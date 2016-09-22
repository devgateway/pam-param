#include <stdio.h>
#include <stdlib.h>
#include <pam_appl.h>

#ifndef SERVICE_NAME
#define SERVICE_NAME "pam-param-test"
#endif

int main() {
	char username[32 + 1];
	int rc;
	struct pam_conv conv;
	pam_handle_t *pamh;

	for (;;) {
		printf("Enter user name: ");
		if ( scanf("%32s", &username) != 1 ) return 0;

		rc = pam_start(SERVICE_NAME, username, &conv, &pamh);
		if (rc != PAM_SUCCESS) return 1;

		rc = pam_acct_mgmt(pamh, 0);
		puts( pam_strerror(pamh, rc) );

		rc = pam_end(pamh, rc);
		if (rc != PAM_SUCCESS) return 1;
	}
}
