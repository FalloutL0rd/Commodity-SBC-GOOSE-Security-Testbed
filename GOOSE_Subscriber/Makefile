# ==================================================================
# Makefile for GOOSE Subscriber Simulation Environment
# ------------------------------------------------------------------
# Builds:
#   - subscriber_engine: internal background daemon (non-user)
#   - subscription_manager: user-facing CLI controller
# ==================================================================

CC = gcc
CFLAGS = -O2 -g -Wall -Wextra -I/usr/local/include -I/usr/local/include/libiec61850
PKGFLAGS = $(shell pkg-config --cflags --libs libiec61850 json-c)

SRC_ENGINE = src/sub_engine.c src/sub_config_loader.c src/sub_core.c
SRC_MANAGER = src/subscription_manager.c

all: subscriber_engine subscription_manager
	@echo ""
	@echo "Build complete!"
	@echo "Run: sudo ./subscription_manager"
	@echo ""

subscriber_engine: $(SRC_ENGINE)
	$(CC) $(CFLAGS) -o $@ $(SRC_ENGINE) $(PKGFLAGS)

subscription_manager: $(SRC_MANAGER)
	$(CC) $(CFLAGS) -o $@ $(SRC_MANAGER) $(PKGFLAGS)

clean:
	rm -f subscriber_engine subscription_manager
