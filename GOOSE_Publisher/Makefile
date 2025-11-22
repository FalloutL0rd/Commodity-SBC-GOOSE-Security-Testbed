# ==================================================================
# Makefile for GOOSE Publisher Simulation Environment
# ------------------------------------------------------------------
# Builds:
#   - publisher_engine: internal background daemon
#   - publication_manager: user-facing CLI controller
# ==================================================================

CC = gcc
CFLAGS = -O2 -g -Wall -Wextra -I/usr/local/include -I/usr/local/include/libiec61850
PKGFLAGS = $(shell pkg-config --cflags --libs libiec61850 json-c)

# --- minimal additions for optional HMAC support ---
AUTH_SRCS = src/auth_security.c src/auth_hmac.c src/auth_canon.c
CRYPTO_LIBS = -lcrypto
# ---------------------------------------------------

SRC_ENGINE = src/publisher_engine.c src/config_loader.c src/mms_helpers.c src/publisher_core.c $(AUTH_SRCS)
SRC_MANAGER = src/publication_manager.c

# Default build target
all: publisher_engine publication_manager
	@echo ""
	@echo "Build complete!"
	@echo "Run the manager with: sudo ./publication_manager"
	@echo ""

# ------------------------------------------------------------------
# Internal GOOSE publisher engine (non-user)
# ------------------------------------------------------------------
publisher_engine: $(SRC_ENGINE)
	$(CC) $(CFLAGS) -o $@ $(SRC_ENGINE) $(PKGFLAGS) $(CRYPTO_LIBS)

# ------------------------------------------------------------------
# Main user-facing control program
# ------------------------------------------------------------------
publication_manager: $(SRC_MANAGER)
	$(CC) $(CFLAGS) -o $@ $(SRC_MANAGER) $(PKGFLAGS)

# ------------------------------------------------------------------
# Cleanup build artifacts
# ------------------------------------------------------------------
clean:
	rm -f publisher_engine publication_manager
