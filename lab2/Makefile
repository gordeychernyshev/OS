CC = gcc
CFLAGS = -Wall -Wextra -Werror -pthread -fPIC
LDFLAGS = -pthread
TARGET = secure_copy
LIB = libcaesar.so

all: $(LIB) $(TARGET)

$(LIB): caesar.o
	$(CC) -shared -o $(LIB) caesar.o

caesar.o: caesar.c caesar.h
	$(CC) $(CFLAGS) -c caesar.c -o caesar.o

secure_copy: secure_copy.c caesar.h $(LIB)
	$(CC) secure_copy.c -L. -lcaesar $(LDFLAGS) -o $(TARGET)

clean:
	rm -f *.o $(TARGET) $(LIB)