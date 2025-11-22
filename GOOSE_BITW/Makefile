# ==================================================================
# Makefile for GOOSE BITW (Bridge-in-the-Wire)
# ==================================================================
CC = gcc
CFLAGS = -O2 -g -Wall -Wextra
PKGFLAGS = -I/usr/include/json-c -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -I/usr/include/libnl3 -ljson-c -lpcap
LIBS = -lcrypto

ENGINE_SRCS = src/bitw_engine.c src/bitw_policy_loader.c \
              src/goose_parse.c src/auth_hmac.c src/freshness.c

MANAGER_SRCS = src/bitw_manager.c

all: bitw_engine bitw_manager
	@echo ""; echo "Build complete!"; echo "Run the manager with: sudo ./bitw_manager"; echo ""

bitw_engine: $(ENGINE_SRCS)
	$(CC) $(CFLAGS) -o $@ $(ENGINE_SRCS) $(PKGFLAGS) $(LIBS)

bitw_manager: $(MANAGER_SRCS)
	$(CC) $(CFLAGS) -o $@ $(MANAGER_SRCS) -I/usr/include/json-c -ljson-c

clean:
	rm -f bitw_engine bitw_manager
