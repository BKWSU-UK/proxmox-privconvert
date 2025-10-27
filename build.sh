#!/bin/bash
#
# Build script for privconvert - checks dependencies and builds the program
#

set -e

echo "Proxmox privconvert build script"
echo "================================="
echo

# Check for GCC
if ! command -v gcc &> /dev/null; then
    echo "ERROR: GCC compiler not found"
    echo "Install with: apt install build-essential"
    exit 1
fi

echo "✓ GCC found: $(gcc --version | head -n1)"

# Check for libacl headers
if [ ! -f /usr/include/sys/acl.h ] && [ ! -f /usr/local/include/sys/acl.h ]; then
    echo
    echo "ERROR: libacl development files not found"
    echo
    echo "To install on Debian/Ubuntu:"
    echo "  sudo apt install libacl1-dev"
    echo
    echo "To install on RHEL/CentOS/Fedora:"
    echo "  sudo dnf install libacl-devel"
    echo "  or"
    echo "  sudo yum install libacl-devel"
    echo
    exit 1
fi

echo "✓ libacl development files found"

# Check for static libraries (warn if not found)
STATIC_LIB_FOUND=0
for path in /usr/lib /usr/lib64 /usr/lib/x86_64-linux-gnu /usr/local/lib /usr/local/lib64; do
    if [ -f "$path/libacl.a" ]; then
        STATIC_LIB_FOUND=1
        echo "✓ Static libacl found: $path/libacl.a"
        break
    fi
done

if [ $STATIC_LIB_FOUND -eq 0 ]; then
    echo "⚠ Warning: Static libacl.a not found"
    echo "  Static build may fail. Building dynamic version instead."
    echo
    echo "Building dynamic version..."
    make dynamic
else
    echo
    echo "Building static version..."
    make
fi

echo
echo "✓ Build successful!"
echo
echo "Executable: ./privconvert"
echo "File size: $(du -h privconvert | cut -f1)"
echo

# Check if statically linked
if ldd privconvert 2>&1 | grep -q "not a dynamic executable"; then
    echo "Type: Statically linked (no dependencies)"
else
    echo "Type: Dynamically linked"
    echo "Dependencies:"
    ldd privconvert | sed 's/^/  /'
fi

echo
echo "To install system-wide:"
echo "  sudo make install"
echo
echo "To test:"
echo "  sudo ./privconvert <container_number> <privileged|unprivileged>"
