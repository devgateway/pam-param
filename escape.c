#include <stdlib.h>
#include <string.h>

/* Escape a string to be used in search filter.
Args:
	string - string to escape
Returns:
	escaped string or NULL
Copyright:
	This function is based on PHP implementation of ldap_escape, see COPYING-php  */
char *ldap_escape_filter(const char *string) {
	char map[256] = { 0 };
	const char unsafe[] = "\\*()\0";
	const char hex[] = "0123456789abcdef";
	char *result;
	int i = 0, p = 0;
	size_t len = 1;

	if (!string) return NULL;

	/* map unsafe character */
	for (i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
		map[(unsigned char) unsafe[i]] = 1;
	}

	/* count required memory for the result string */
	for (i = 0; i < strlen(string); i++) {
		len += (map[(unsigned char) string[i]]) ? 3 : 1;
	}

	result = (char *) malloc(len);
	if (!result) return NULL;

	for (i = 0; i < strlen(string); i++) {
		unsigned char v = (unsigned char) string[i];

		if (map[v]) {
			result[p++] = '\\';
			result[p++] = hex[v >> 4];
			result[p++] = hex[v & 0x0f];
		} else {
			result[p++] = v;
		}
	}

	result[p++] = '\0';
	return result;
}
