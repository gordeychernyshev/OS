CC = gcc
CFLAGS = -Wall -Wextra -Werror -pthread -fPIC
LDFLAGS = -pthread -Wl,-rpath=.
TARGET = secure_copy
MOUNT_TARGET = secure_mount
LIB = libcaesar.so
FUSE_CFLAGS = $(shell pkg-config --cflags fuse3)
FUSE_LIBS = $(shell pkg-config --libs fuse3)

all: $(LIB) $(TARGET) $(MOUNT_TARGET)

$(LIB): caesar.o secure_key.o
	$(CC) -shared -o $(LIB) caesar.o secure_key.o -pthread

caesar.o: caesar.c caesar.h secure_key.h
	$(CC) $(CFLAGS) -c caesar.c -o caesar.o

secure_key.o: secure_key.c secure_key.h
	$(CC) $(CFLAGS) -c secure_key.c -o secure_key.o

rc4.o: rc4.c rc4.h
	$(CC) $(CFLAGS) -c rc4.c -o rc4.o

disk_image.o: disk_image.c disk_image.h rc4.h
	$(CC) $(CFLAGS) -c disk_image.c -o disk_image.o

$(TARGET): secure_copy.c caesar.h secure_key.h disk_image.h $(LIB) disk_image.o rc4.o
	$(CC) $(CFLAGS) secure_copy.c disk_image.o rc4.o -L. -lcaesar $(LDFLAGS) -o $(TARGET)

$(MOUNT_TARGET): secure_mount.c disk_image.h disk_image.o rc4.o
	$(CC) $(CFLAGS) $(FUSE_CFLAGS) secure_mount.c disk_image.o rc4.o $(FUSE_LIBS) -o $(MOUNT_TARGET)

clean:
	rm -f *.o $(TARGET) $(MOUNT_TARGET) $(LIB)
