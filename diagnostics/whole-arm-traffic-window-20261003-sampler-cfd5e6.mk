# Standalone diagnostic; invoked only through the project Docker build script.
# Root copies this Makefile and qdx-uniform-cpu.c into an isolated build folder.
ifndef TOPDIR
$(error TOPDIR must name the actual isolated OpenWrt tree inside Docker)
endif
TOOLCHAIN := $(TOPDIR)/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.4.0_musl
export STAGING_DIR := $(TOPDIR)/staging_dir
CC := $(TOOLCHAIN)/bin/aarch64-openwrt-linux-musl-gcc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror
.PHONY: all
all: qdx-uniform-cpu
qdx-uniform-cpu: qdx-uniform-cpu.c
	$(CC) $(CFLAGS) -o $@ $<
	chmod 0755 $@
