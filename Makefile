PREFIX = /usr/local

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

CFLAGS += -Wall -Wextra -Werror -Wno-unused-but-set-variable -pedantic -std=c99
LDFLAGS += -lcrypto

all: CFLAGS += -c
all: totp docs

%.o: %.c
	@$(CC) $< $(CFLAGS) -o $@
	@echo "[CC] $@"

totp: $(OBJS)
	@$(CC) $^ $(LDFLAGS) -o $@
	@echo "[LD] $@"

debug: CFLAGS += -g -fsanitize=address -fsanitize=undefined
debug: $(SRCS)
	$(CC) $^ $(CFLAGS) $(LDFLAGS) -o $@

.PHONY: docs
docs:
	@scdoc < totp.1.scd > totp.1
	@echo "[SCDOC] $@"

.PHONY: install
install: all
	mkdir -p ${PREFIX}/bin
	cp totp "${PREFIX}/bin"
	chmod 755 "${PREFIX}/bin/totp"
	mkdir -p "${PREFIX}/share/man/man1"
	cp totp.1 "${PREFIX}/share/man/man1"
	chmod 644 "${PREFIX}/share/man/man1/totp.1"

.PHONY: clean
clean:
	rm -rf $(OBJS) totp debug debug.dSYM totp.1
