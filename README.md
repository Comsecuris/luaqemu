LuaQEMU
=======

LuaQEMU is a [QEMU-based](http://www.qemu.org/) framework exposing several of QEMU-internal APIs to a [LuaJIT](http://luajit.org/) core injected into QEMU itself. Among other things, this allows fast prototyping of target systems without any native code and minimal effort in Lua.

When initially evaluating the idea of LuaQEMU, we had the following specific functional requirements:

  * Mature multi-architecture support
  * Full-system emulation support, including drivers and peripherals, MMU, interrupts, and timers
  * Ease of long-term maintainability (i.e. little to no QEMU core modifications)
  * Easy target prototyping (e.g. definition of specific boards) without native code

The first two properties are almost provided by QEMU out of the box. We gain flexibility for target prototyping, by being able to completely write board definitions in Lua without native code. We have implemented this such that each hardware architecture comes with a newly introduced Lua-board, which can be used to interact and source from other native board definitions, while not requiring to modify QEMU core code. For the time being we focused on ARM support here, but this approach can be easily transferred to other architectures supported by QEMU.

At the moment there is no API documentation. Please have a look at the files in hw/arm/luaqemu.

**Important Notice**: At the moment this project is WIP and has to be considered unstable. If you run into issues feel free to let us know (patches welcome!), but don't be surprised about unexpected behaviour.

For more information have a look at our first [blog post](https://comsecuris.com/blog/posts/luaqemu_bcm_wifi/) introducing LuaQEMU.

Building
========

Install regular QEMU dependencies + luajit, then:

```
git submodule update --init dtc
./configure  --enable-luajit --target-list=arm-softmmu
make
```
