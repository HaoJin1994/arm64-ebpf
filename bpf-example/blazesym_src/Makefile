TARGET_SO = libblazesym_api.so
TARGET_A  = libblazesym_api.a
OBJ       = blazesym_api.o
SRC       = blazesym_api.c

CROSS     = aarch64-linux-gnu-
CC        = $(CROSS)gcc
AR        = $(CROSS)ar

BLAZESYM_INC = /home/jin/arm64_lib/blazesym/capi/include
BLAZESYM_LIB = /home/jin/arm64_lib/lib

CFLAGS  = -Wall -fPIC
CFLAGS += -I$(BLAZESYM_INC)

LDFLAGS_SO  = -shared
LDFLAGS_SO += -L$(BLAZESYM_LIB) -lblazesym_c -lelf -lz -lpthread -ldl

all: $(TARGET_SO) $(TARGET_A)

$(OBJ): $(SRC) blazesym_api.h Makefile
	$(CC) $(CFLAGS) -c -o $@ $(SRC)

$(TARGET_SO): $(OBJ) Makefile
	$(CC) $(LDFLAGS_SO) -o $@ $(OBJ) -Wl,-rpath,$(BLAZESYM_LIB)

$(TARGET_A): $(OBJ)
	$(AR) rcs $@ $(OBJ)

clean:
	rm -f $(TARGET_SO) $(TARGET_A) $(OBJ)

.PHONY: all clean