# Display exported symbols:
#  nm -D libsecure_pkcs11_https.so | grep ' T '

SRC_DIR=../../src

CC= gcc
ARCH_FLAGS= -m64
CFLAGS= $(ARCH_FLAGS) -Wall -Wextra -O2 -I$(SRC_DIR) -fPIC -std=c11
LDFLAGS= -lcurl -lssl -lcrypto -lpthread
LIBNAME=libsecure_pkcs11_https.so

all: empty-pkcs11.o https_client.o
	$(CC) $(ARCH_FLAGS) -shared -o $(LIBNAME) \
	-Wl,-soname,$(LIBNAME) \
	-Wl,--version-script,empty-pkcs11.version \
	empty-pkcs11.o https_client.o $(LDFLAGS)
	strip --strip-all $(LIBNAME)

empty-pkcs11.o: $(SRC_DIR)/empty-pkcs11.c $(SRC_DIR)/empty-pkcs11.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/empty-pkcs11.c

https_client.o: $(SRC_DIR)/https_client.c $(SRC_DIR)/https_client.h
	$(CC) $(CFLAGS) -c $(SRC_DIR)/https_client.c

clean:
	-rm -f *.o

distclean: clean
	-rm -f *.so
