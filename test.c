#include <stdio.h>
#include <stdlib.h>
#include <pam_appl.h>

#ifndef SERVICE_NAME
#define SERVICE_NAME "pam-param-test"
#endif

int main() {
	char username[32 + 1];
	int rc;

	for (;;) {
		printf("Enter user name: ");
		if ( scanf("%32s", &username) != 1 ) return 1;
	}
}
