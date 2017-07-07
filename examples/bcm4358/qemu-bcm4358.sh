#!/bin/sh
# Copyright (c) 2017 Comsecuris UG (haftungsbeschraenkt)

QEMU=arm-softmmu/qemu-system-arm
BOARD_LUA=examples/bcm4358/bcm4358.lua

${QEMU} -M luaarm -nographic -lua ${BOARD_LUA} -m 4G "$@" -kernel examples/bcm4358/bcm4358.patchram.bin -S
