#!/bin/sh
set -eu

cd "$(dirname "$0")"
CXXFLAGS="-std=c++17 -Wall -Wextra -O2 -static"

CXX=x86_64-w64-mingw32-g++
WINDRES=x86_64-w64-mingw32-windres

DLLFLAGS="-shared -std=c++17 -Wall -Wextra -O2 -static -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000"

$CXX $DLLFLAGS -o build/nimbus_src.dll \
	src/main/dllmain.cpp src/main/IatHook.cpp src/main/InlineHook.cpp src/main/NimbusConfig.cpp src/main/ReflectiveLoader.cpp

python3 - <<'PYEOF'
import struct
path = 'build/nimbus_src.dll'
data = bytearray(open(path, 'rb').read())
pe = struct.unpack_from('<I', data, 0x3C)[0]
opt = pe + 0x18
magic = struct.unpack_from('<H', data, opt)[0]
dd = opt + (0x70 if magic == 0x20b else 0x60)
tls = dd + 9 * 8
rva, size = struct.unpack_from('<II', data, tls)
print('tls dir before:', hex(rva), size)
struct.pack_into('<II', data, tls, 0, 0)
open(path, 'wb').write(data)
print('tls dir stripped')
PYEOF

(cd build && $WINDRES ../src/main/installer.rc -O coff -o installer.res.o)

$CXX -municode $CXXFLAGS -o build/nimbus_installer.exe \
	src/main/main.cpp build/installer.res.o -ladvapi32

$CXX -municode $CXXFLAGS -o build/test.exe \
	src/test/test.cpp -lntdll -ladvapi32 -liphlpapi -lws2_32

echo "build ok:"
ls -la build
