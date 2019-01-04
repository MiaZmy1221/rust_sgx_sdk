SGX_SDK ?= /opt/intel/sgxsdk
CURRENT ?= ./
CFLAGS := -O2 -fPIC -Wno-attributes
INCLUDEDIRS := -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include -I$(CURRENT)

SRCS := $(wildcard *.c)
OBJS := $(sort $(SRCS:.c=.o))

TARGET  := libmerkle_t.a

.PHONY: all
all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcsD $@ $^

$(OBJS): %.o: %.c
	$(CC) -c $(CFLAGS) $(INCLUDEDIRS) $< -o $@

.PHONY: clean
clean:
	@$(RM) $(OBJS) $(TARGET)
