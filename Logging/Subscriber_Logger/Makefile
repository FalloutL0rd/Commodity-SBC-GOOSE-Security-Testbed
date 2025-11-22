CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lpcap

TARGET  = subscriber_logger
SRC     = src/logger.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)