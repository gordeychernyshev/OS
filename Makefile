CC      := gcc
CFLAGS  := -Wall -Wextra -pedantic -fPIC -O2
LDFLAGS := -shared

TARGET  := lib.so
SRC     := caesar.c
HDR     := caesar.h

.PHONY: all install test clean

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)

install: $(TARGET)
	install -m 0755 $(TARGET) /usr/local/lib/$(TARGET)
	ldconfig

test: $(TARGET)
	@python3 test.py ./$(TARGET) X input.txt encrypted.bin
	@python3 test.py ./$(TARGET) X encrypted.bin decrypted.txt
	@cmp input.txt decrypted.txt

clean:
	rm -f $(TARGET) encrypted.bin decrypted.txt
