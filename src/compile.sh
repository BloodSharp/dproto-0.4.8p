#!/bin/sh
#
exec 2>/dev/null
mkdir bin
rm -f bin/dproto_i386.so

exec 2>compile.log

icc 	-mia32 -O3 -fasm-blocks \
		-funroll-loops \
		-fomit-frame-pointer \
		-fno-rtti \
		-s \
		-fno-stack-protector \
		-falign-functions=2 \
		-Wno-unknown-pragmas \
		-static-intel -shared  \
		-static-libgcc \
		-fno-builtin \
		-fno-exceptions \
-I. -I../metamod -I../../hlsdk/multiplayer/engine -I../../hlsdk/multiplayer/common -I../../hlsdk/multiplayer/pm_shared -I../../hlsdk/multiplayer/dlls -I../../hlsdk/multiplayer \
dllapi.cpp engine_api.cpp h_export.cpp meta_api.cpp \
dproto.cpp sdk_util.cpp  cfg.cpp HookTools.cpp engine_data.cpp plr_list.cpp \
dproto_shared.cpp memu.cpp subserver.cpp bspec.cpp \
dynpatcher_base.cpp \
b-spec/BS_Linux_Dynamic.cpp b-spec/dynparser_linux.cpp \
-ldl -lm \
-o bin/dproto_i386.so
