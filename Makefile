# GhostLock A17 (rebuilt tree) — NDK r30 on macOS (darwin-x86_64)
API ?= 35

NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(HOME)/Library/Android/sdk/ndk/30.0.15729638)
HOST_TAG := $(shell uname -m | sed 's/x86_64/darwin-x86_64/;s/arm64/darwin-x86_64/')
NDK_CC := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(HOST_TAG)/bin/aarch64-linux-android$(API)-clang

SRCS := \
  src/core/main.c \
  src/core/util.c \
  src/core/slide.c \
  src/core/fops.c \
  src/core/pipe_physrw.c \
  src/core/pipe_reclaim.c \
  src/core/rwforge_a17.c \
  src/core/root.c \
  src/core/miniadb.c \
  src/core/umh_root.c

CFLAGS := -O2 -Wall -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  -Isrc/core -Isrc/devices -DTARGET_CONFIG_H=\"target.h\"
LDFLAGS := -fPIE -pie -pthread

.PHONY: all clean

all: ghostlock

ghostlock: $(SRCS)
	$(NDK_CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f ghostlock
