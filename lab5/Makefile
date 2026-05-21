CC = gcc
CFLAGS = -Wall -Wextra -Werror -pthread -fPIC
LDFLAGS = -pthread -Wl,-rpath=.
TARGET = secure_copy
LIB = libcaesar.so

all: $(LIB) $(TARGET)

$(LIB): caesar.o secure_key.o
	$(CC) -shared -o $(LIB) caesar.o secure_key.o -pthread

caesar.o: caesar.c caesar.h secure_key.h
	$(CC) $(CFLAGS) -c caesar.c -o caesar.o

secure_key.o: secure_key.c secure_key.h
	$(CC) $(CFLAGS) -c secure_key.c -o secure_key.o

$(TARGET): secure_copy.c caesar.h secure_key.h $(LIB)
	$(CC) secure_copy.c -L. -lcaesar $(LDFLAGS) -o $(TARGET)

clean:
	rm -f *.o $(TARGET) $(LIB)