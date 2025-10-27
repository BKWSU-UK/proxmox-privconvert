CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -D_GNU_SOURCE
LDFLAGS = -static
LIBS = -lacl

TARGET = privconvert
SOURCE = privconvert.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)
	strip $(TARGET)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Build without static linking (for development/testing)
dynamic: $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

# Show required dependencies for static build
deps:
	@echo "For static compilation, you need:"
	@echo "  - libacl-dev (Debian/Ubuntu: apt install libacl1-dev)"
	@echo "  - Static libraries may require additional packages on some systems"
