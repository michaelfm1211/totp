#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "colors.h"

#define ERROR_NO_SERVICES "error: no services have been configured\n"

// macros to iterate the config file line-by-line. used heavily
#define ITER_CONFIG \
	char *line = NULL; \
	size_t linecap = 0; \
	ssize_t linelen; \
	int linenum = 0; \
	while ((linelen = getline(&line, &linecap, config)) > 0) {
#define ITER_CONFIG_END \
		linenum++; \
	} \
	free(line);

long config_len;
FILE *config;

enum flags {
	RAW_OUT = 0x1
};

FILE *config_open(long *len) {
	char *path = NULL;
	char *xdg_config_env = getenv("XDG_CONFIG_HOME");
	if (xdg_config_env) {
		path = calloc(strlen(xdg_config_env)+14, 1);
		sprintf(path, "%s/totp_secrets", xdg_config_env);
	} else {
		char *home_env = getenv("HOME");
		if (!home_env) {
			fprintf(stderr, "error: $HOME is not set\n");
			exit(1);
		}
		path = calloc(strlen(home_env)+22, 1);
		sprintf(path, "%s/.config/totp_secrets", home_env);
	}

	FILE *file = fopen(path, "r+");
	free(path);

	fseek(file, 0, SEEK_END);
	*len = ftell(file);
	rewind(file);

	return file;
}

// print usage to stderr
void usage() {
	fprintf(stderr, "usage: totp [-rlh] [-s secrets_file] "
		"[-a service:secret] [-d service] [services...]\n");
}

// remove a service from the config file
int delete_service(const char *service) {
	if (config_len == 0) {
		fprintf(stderr, ERROR_NO_SERVICES);
		return 1;
	}

	char *buf = calloc(config_len+1, 1);
	size_t buflen = 0;

	ITER_CONFIG
		char entry[strlen(line) + 1];
		strcpy(entry, line);

		char *colon = strchr(entry, ':');
		if (!colon) {
			fprintf(stderr,
					"error: syntax error in secrets file on line %d\n", 
					linenum);
			free(buf);
			free(line);
			return 1;
		}
		*colon = '\0';

		if (strcmp(entry, service) != 0) {
			strcpy(buf+buflen, line);
			buflen += linelen;
		}
	ITER_CONFIG_END

	rewind(config);
	int res = fputs(buf, config);
	free(buf);
	if (res == EOF) {
		perror("fputs");
		return 1;
	}
	if (ftruncate(fileno(config), buflen) == -1) {
		perror("ftruncate");
		return 1;
	}

	return 0;
}

// add a new service to the config file given a string in the format of
// "service:secret", where secret is base32-encoded
int add_service(const char *str) {
	char *secret = strchr(str, ':')+1;
	if (secret == NULL) {
		fprintf(stderr, "error: argument must be in format \"service"
			":secret\"\n");
		return 1;
	} else if (*(secret+1) == '\0') {
		fprintf(stderr, "error: secret cannot be empty\n");
		return 1;
	} else if (strchr(secret+1, ':') != NULL) {
		fprintf(stderr, "error: secret cannot contain a comma\n");
		return 1;
	}

	char *tmp = secret;
	while (*tmp != '\0') {
		*tmp = toupper(*tmp);
		tmp++;
	}

	int res1 = fputs(str, config);
	int res2 = fputs("\n", config);
	if (res1 == EOF || res2 == EOF) {
		perror("fputs");
		return 1;
	}

	return 0;
}

// list all services and their base32-encoded secrets stored in the config
// file
int list_services() {
	if (config_len == 0) {
		fprintf(stderr, ERROR_NO_SERVICES);
		return 1;
	}

	printf(SGR_BOLD SGR_UNDER "Service\t\tSecret (do not share)\n"
		SGR_RESET);
	ITER_CONFIG
		if (strchr(line, ':') == NULL) {
			fprintf(stderr, SGR_RESET
					"error: syntax error in secrets file on line %d\n", 
					linenum);
			return 1;
		}

		char *secret = NULL;
		char *service = strtok_r(line, ":", &secret);
		printf(SGR_BOLD"%s"SGR_RESET"\t\t%s", service, secret);
	ITER_CONFIG_END

	return 0;
}

// return the base32-encoded secret for a service in the config file as a
// heap allocated string
char *get_secret(const char *service) {
	if (config_len == 0) {
		fprintf(stderr, ERROR_NO_SERVICES);
		return NULL;
	}

	ITER_CONFIG
		char *secret = NULL;
		char *entry = strtok_r(line, ":", &secret);
		if (strcmp(service, entry) == 0) {
			char *str = strdup(secret);
			*(strchr(str, '\n')) = 0;
			free(line);
			return str;
		}
	ITER_CONFIG_END

	fprintf(stderr, "error: service '%s' has not been configured\n",
		service);
	return NULL;
}

// returns a heap allocated byte array which contains the base32 decoded
// string, str, and then sets res_len to length of the byte array. adapted
// from https://stackoverflow.com/questions/641361/base32-decoding
unsigned char *decode_base32(const char *str, size_t
	*res_len) {
	size_t str_len = strlen(str);
	*res_len = (5*str_len)/8;
	unsigned char *res = malloc(*res_len);

	unsigned char curbyte = 0, bitsleft = 8;
	int mask = 0, pos = 0;
	for (size_t i = 0; i < str_len; i++) {
		int val;
		if (str[i] < 91 && str[i] > 64){
			val = str[i] - 65;
		} else if (str[i] < 56 && str[i] > 49) {
			val = str[i] - 24;
		} else {
			free(res);
			return NULL;
		}

		if (bitsleft > 5) {
			mask = val << (bitsleft - 5);
			curbyte = curbyte|mask;
			bitsleft -= 5;
		} else {
			mask = val >> (5 - bitsleft);
			curbyte = curbyte|mask;
			res[pos++] = curbyte;
			curbyte = val << (3 + bitsleft);
			bitsleft += 3;
		}
	}

	return res;
}

// return the HOTP value for a service in the config file. uses all the
// default values specified by the RFCs
int hotp_value(const char *secret, unsigned long long count) {
	size_t data_len;
	unsigned char *data = decode_base32(secret, &data_len);
	if (data == NULL) {
		fprintf(stderr, "error while decoding base32-encoded secret"
			"\n");
		return -1;
	}

	unsigned long be_count = htonll(count);

	unsigned char *mac = NULL;
	unsigned int mac_len = -1;
	mac = HMAC(EVP_sha1(), (const void *)data, data_len,
		(unsigned char *)&be_count, sizeof(be_count), mac, &mac_len);
	free(data);

	int off = mac[mac_len - 1] & 0xf;
	int trunc = (mac[off]&0x7f) << 24
		| (mac[off+1] & 0xff) << 16
		| (mac[off+2] & 0xff) <<  8
		| (mac[off+3] & 0xff);
	return trunc % 1000000;
}

int main(int argc, char *argv[]) {
	if (argc == 1) {
		usage();
		return 1;
	}

	config = config_open(&config_len);

	int flags = 0;
	char ch;
	while ((ch = getopt(argc, argv, ":rlhs:a:d:")) != -1) {
		switch (ch) {
		case 'r':
			flags |= RAW_OUT;
			break;
		case 's':
			fclose(config);
			config = config_open(&config_len);
			break;
		case 'a':
			return add_service(optarg);
		case 'd':
			return delete_service(optarg);
		case 'l':
			return list_services();
		case 'h':
		case ':':
		case '?':
			usage();
			return 1;
		}
	}

	unsigned long unix_time = time(NULL);
	unsigned long count = unix_time/30;

	if (!(flags & RAW_OUT))
		printf("Time Left: %lu\n", (count+1)*30 - unix_time);

	for (; optind < argc; optind++) {
		char *secret = get_secret(argv[optind]);
		if (secret == NULL)
			return 1;

		int res = hotp_value(secret, count);
		free(secret);
		if (res == -1)
			return 1;

		if (flags & RAW_OUT) {
			printf("%*d\n", 6, res);
		} else {
			printf("%s\t\t" SGR_BOLD "%06d\n" SGR_RESET, argv[optind], res);
		}
	}

	return 0;
}
