#include "util.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *config_open(long *len) {
  char *path = NULL;
  char *xdg_config_env = getenv("XDG_CONFIG_HOME");
  if (xdg_config_env) {
    path = calloc(strlen(xdg_config_env) + 14, 1);
    sprintf(path, "%s/totp_secrets", xdg_config_env);
  } else {
    char *home_env = getenv("HOME");
    if (!home_env) {
      fprintf(stderr, "error: $HOME is not set\n");
      exit(1);
    }
    path = calloc(strlen(home_env) + 22, 1);
    sprintf(path, "%s/.config/totp_secrets", home_env);
  }

  FILE *file = fopen(path, "r+");
  free(path);

  fseek(file, 0, SEEK_END);
  *len = ftell(file);
  rewind(file);

  return file;
}

bool validate_base32(const char *str) {
  for (unsigned long i = 0; i < strlen(str); i++) {
    if ((str[i] < 50 || str[i] > 55) && (str[i] < 65 || str[i] > 90) &&
        str[i] != '=')
      return false;
  }
  return true;
}

unsigned char *decode_base32(const char *str, size_t *res_len) {
  size_t str_len = strlen(str);
  *res_len = (5 * str_len) / 8;
  unsigned char *res = malloc(*res_len);

  unsigned char curbyte = 0, bitsleft = 8;
  int mask = 0, pos = 0;
  for (size_t i = 0; i < str_len; i++) {
    int val;
    if (str[i] < 91 && str[i] > 64) {
      val = str[i] - 65;
    } else if (str[i] < 56 && str[i] > 49) {
      val = str[i] - 24;
    } else {
      free(res);
      return NULL;
    }

    if (bitsleft > 5) {
      mask = val << (bitsleft - 5);
      curbyte = curbyte | mask;
      bitsleft -= 5;
    } else {
      mask = val >> (5 - bitsleft);
      curbyte = curbyte | mask;
      res[pos++] = curbyte;
      curbyte = val << (3 + bitsleft);
      bitsleft += 3;
    }
  }

  return res;
}

unsigned long long htonl64(unsigned long long in) {
  unsigned long long out;
  unsigned char *ptr = (unsigned char *)&out;
  ptr[0] = in >> 56;
  ptr[1] = in >> 48;
  ptr[2] = in >> 40;
  ptr[3] = in >> 32;
  ptr[4] = in >> 24;
  ptr[5] = in >> 16;
  ptr[6] = in >> 8;
  ptr[7] = in >> 0;
  return out;
}

int hotp_value(const unsigned char *secret, size_t secret_len,
               unsigned long long count) {
  unsigned long long be_count = htonl64(count);

  unsigned char *mac = NULL;
  unsigned int mac_len = -1;
  mac = HMAC(EVP_sha1(), (const void *)secret, secret_len,
             (unsigned char *)&be_count, sizeof(be_count), mac, &mac_len);

  int off = mac[mac_len - 1] & 0xf;
  int trunc = (mac[off] & 0x7f) << 24 | (mac[off + 1] & 0xff) << 16 |
              (mac[off + 2] & 0xff) << 8 | (mac[off + 3] & 0xff);
  return trunc % 1000000;
}
