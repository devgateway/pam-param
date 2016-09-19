#include <stdio.h>
#include <pam_appl.h>

#define FAIL 1
#define PASS 0

int main(int argc, const char *argv[]) { 
	if (argc != 2) {
		fprintf(stderr, "One argument required: user name.\n");
		return FAIL;
	}
}
