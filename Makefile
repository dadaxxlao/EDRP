# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2024 EDRP Project

# 二进制名称
APP = edrp_socket

# 源文件
SRCS-y := socket/socket.c \
          socket/tcp.c \
          socket/udp.c \
          socket/arp.c

# 头文件目录
CFLAGS += -Isocket/

# 使用pkg-config构建(如果可用)
ifeq ($(shell pkg-config --exists libdpdk && echo 0),0)

all: shared static
.PHONY: shared static
shared: build/$(APP)-shared
	cp -f build/$(APP)-shared build/$(APP)
static: build/$(APP)-static
	cp -f build/$(APP)-static build/$(APP)

PKGCONF=pkg-config --define-prefix

PC_FILE := $(shell $(PKGCONF) --path libdpdk)
CFLAGS += -O3 -g $(shell $(PKGCONF) --cflags libdpdk)
CFLAGS += -DALLOW_EXPERIMENTAL_API
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = -Wl,-Bstatic $(shell $(PKGCONF) --static --libs libdpdk)

# 添加pthread库
LDFLAGS_SHARED += -pthread
LDFLAGS_STATIC += -pthread

# 生成动态库
build/lib$(APP).so: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) -fPIC -shared $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS_SHARED)

# 生成静态库
build/lib$(APP).a: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) -c $(CFLAGS) $(SRCS-y)
	ar rcs $@ *.o
	rm -f *.o

# 生成可执行文件
build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared build/lib$(APP).so build/lib$(APP).a
	rm -f *.o
	test -d build && rmdir -p build || true

else # 使用传统构建系统

ifeq ($(RTE_SDK),)
$(error "请定义RTE_SDK环境变量")
endif

# 默认目标，通过查找带有.config的路径来检测构建目录
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

ifneq ($(CONFIG_RTE_EXEC_ENV_LINUX),y)
$(error 此应用程序只能在Linux环境中运行)
endif

CFLAGS += -O3
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -Isocket/

include $(RTE_SDK)/mk/rte.extapp.mk
endif
