BIN     := amfi-allow
SRC     := amfi-allow.c
CFLAGS  := -arch arm64e -O2 -Wall -Wextra
LDFLAGS := -framework CoreFoundation -framework Security

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC)
	clang $(CFLAGS) $(LDFLAGS) -o $@ $<
	codesign --force --sign - $@

clean:
	rm -f $(BIN)
