CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -Isrc -std=c99 -Wall -Wextra -Wno-unused-parameter -D_FILE_OFFSET_BITS=64 -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDLIBS += -lz

have = $(shell printf '#include <$(1)>\nint main(void){return 0;}\n' | $(CC) -x c - -o /dev/null $(2) >/dev/null 2>&1 && echo yes)
ifeq ($(call have,brotli/decode.h,-lbrotlidec),yes)
CFLAGS += -DHAVE_BROTLI
LDLIBS += -lbrotlidec -lbrotlicommon
endif
ifeq ($(call have,lzma.h,-llzma),yes)
CFLAGS += -DHAVE_LZMA
LDLIBS += -llzma
endif
ifeq ($(call have,bzlib.h,-lbz2),yes)
CFLAGS += -DHAVE_BZ2
LDLIBS += -lbz2
endif
ifeq ($(call have,zstd.h,-lzstd),yes)
CFLAGS += -DHAVE_ZSTD
LDLIBS += -lzstd
endif
PREFIX ?= /usr/local

SRC := $(shell find src -name '*.c' | sort)
HDR := $(shell find src -name '*.h')
OBJ := $(SRC:src/%.c=build/%.o)
BIN := aerompatch

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c $(HDR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(BIN)
	sh tests/run.sh

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -rf build $(BIN)

.PHONY: all test install clean
