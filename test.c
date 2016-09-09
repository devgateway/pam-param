#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "inih/ini.h"
#include "pam-param.h"

#define FAIL 1
#define PASS 0

extern config cfg;

int main(int argc, const char *argv[]) { 
	int rc;
	char host_name[HOST_NAME_MAX];
	const char **user_name;
	LDAP *ld;
	struct berval cred;

	if (argc != 2) {
		fprintf(stderr, "One numeric argument required: test number.\n");
		return FAIL;
	}

	int test = atoi(argv[1]);

	switch (test) {
		case 0:
			rc = ini_parse(CONFIG_FILE, handler, NULL);
			return rc ? FAIL : PASS;

            /* get user name from PAM */
            rc = pam_get_user(pamh, user_name, NULL);
			return rc ? FAIL : PASS;

			/* TODO: connect to LDAP */
            /* connect to LDAP */
            rc = ldap_initialize(&ld, cfg.ldap_uri);
			return rc ? FAIL : PASS;

            cred.bv_val = cfg.ldap_pw;
            cred.bv_len = strlen(cfg.ldap_pw);
            rc = ldap_sasl_bind_s(ld, cfg.ldap_dn, LDAP_SASL_SIMPLE, &cred, NULL, NULL, NULL);
			return rc ? FAIL : PASS;

			/* TODO: check if is super admin */

		case 1:
            /*to test escaped use: string = "\\this*is(a)test\0";*/
			rc = gethostname(host_name, HOST_NAME_MAX);
			if (rc) return FAIL;
			if (cfg.short_name) shorten_name(host_name, HOST_NAME_MAX);
			return PASS;

			/* TODO: check if access permitted */

            /*disconnect from LDAP */
            rc = ldap_unbind_ext(ld, NULL, NULL);
			return rc ? FAIL : PASS;

		default:
			fprintf(stderr, "Invalid test number: %i.\n", test);
			return FAIL;
	}
}
