#include "pam-param.c"
#define FAIL 1
#define PASS 0

int main(int argc, const char *argv[]) { 
	int rc;
	char host_name[HOST_NAME_MAX];

	if (argc != 2) {
		fprintf(stderr, "One numeric argument required: test number.\n");
		return FAIL;
	}

	int test = atoi(argv[1]);

	switch (test) {
		case 0:
			rc = ini_parse(CONFIG_FILE, handler, NULL);
			return rc ? FAIL : PASS;

			/* TODO: get user name from PAM */

			/* TODO: connect to LDAP */

			/* TODO: check if is super admin */

		case 1:
			rc = gethostname(host_name, HOST_NAME_MAX);
			if (rc) return FAIL;
			if (cfg.short_name) shorten_name(host_name, HOST_NAME_MAX);
			return PASS;

			/* TODO: check if access permitted */

			/* TODO: disconnect from LDAP */
		default:
			fprintf(stderr, "Invalid test number: %i.\n", test);
			return FAIL;
	}
}
