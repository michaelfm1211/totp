#include <arpa/inet.h>
#include <ctype.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "colors.h"
#include "util.h"

// macros to iterate the config file line-by-line. used heavily
#define ITER_CONFIG   \
  char *line = NULL;  \
  size_t linecap = 0; \
  ssize_t linelen;    \
  int linenum = 0;    \
  while ((linelen = getline(&line, &linecap, config)) > 0) {
#define ITER_CONFIG_END \
  linenum++;            \
  }                     \
  free(line);

long config_len;
FILE *config;

// print usage to stderr
void usage(void) {
  fprintf(stderr,
          "usage: totp [-rlh] [-c secrets_file] "
          "[-a service:secret] [-d service] [services...]\n");
}

// remove a service from the config file
int delete_service(const char *service) {
  if (config_len == 0) {
    fprintf(stderr, ERROR_NO_SERVICES);
    return 1;
  }

  char *buf = calloc(config_len + 1, 1);
  size_t buflen = 0;

  ITER_CONFIG
  char entry[strlen(line) + 1];
  strcpy(entry, line);

  char *colon = strchr(entry, ':');
  if (!colon) {
    fprintf(stderr, "error: syntax error in secrets file on line %d\n",
            linenum);
    free(buf);
    free(line);
    return 1;
  }
  *colon = '\0';

  if (strcmp(entry, service) != 0) {
    strcpy(buf + buflen, line);
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
  char *secret = strchr(str, ':') + 1;
  if (secret == (char *)1) {
    fprintf(stderr,
            "error: argument must be in format \"service"
            ":secret\"\n");
    return 1;
  }

  char *tmp = secret;
  while (*tmp != '\0') {
    *tmp = toupper(*tmp);
    tmp++;
  }

  if (!validate_base32(secret)) {
    fprintf(stderr, "error: secret is not valid base32\n");
    return 1;
  }

  fseek(config, 0, SEEK_END);
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
int list_services(void) {
  if (config_len == 0) {
    fprintf(stderr, ERROR_NO_SERVICES);
    return 1;
  }

  printf(SGR_BOLD SGR_UNDER "Service\t\tSecret (do not share)\n" SGR_RESET);
  ITER_CONFIG
  if (strchr(line, ':') == NULL) {
    fprintf(stderr,
            SGR_RESET "error: syntax error in secrets file on line %d\n",
            linenum);
    return 1;
  }

  char *secret = NULL;
  char *service = strtok_r(line, ":", &secret);
  printf(SGR_BOLD "%s" SGR_RESET "\t\t%s", service, secret);
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

  fprintf(stderr, "error: service '%s' has not been configured\n", service);
  return NULL;
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
      case 'c':
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

  unsigned long long unix_time = time(NULL);
  unsigned long long count = unix_time / 30;

  if (!(flags & RAW_OUT))
    printf("Time Left: %llu\n", (count + 1) * 30 - unix_time);

  for (; optind < argc; optind++) {
    char *secret = get_secret(argv[optind]);
    if (secret == NULL) return 1;

    size_t data_len;
    unsigned char *data = decode_base32(secret, &data_len);

    int res = hotp_value(data, data_len, count);
    free(secret);
    free(data);
    if (res == -1) return 1;

    if (flags & RAW_OUT) {
      printf("%06d\n", res);
    } else {
      printf("%s\t\t" SGR_BOLD "%06d\n" SGR_RESET, argv[optind], res);
    }
  }

  return 0;
}
