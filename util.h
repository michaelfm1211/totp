#pragma once

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define ERROR_NO_SERVICES "error: no services have been configured\n"

enum flags {
	RAW_OUT = 0x1
};

// Returns the config file handler. Sets *len to the length of the config file
FILE *config_open(long *len);

// Returns true if str is valid base32, otherwise false.
bool validate_base32(const char *str);
// Returns a malloc'd byte array of data decodded from str. Sets *res_len to
// the length of that byte array. If an error occurs, returns NULL.
unsigned char *decode_base32(const char *str, size_t *res_len);

// Returns the HOTP value for byte array secret of length secret_len and
// counter count.
int hotp_value(const unsigned char *secret, size_t secret_len, unsigned long
		long count);

