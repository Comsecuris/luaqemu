This serves as an example for how to use LuaQemu to trigger the [TDLS setup confirm heap overflow](https://bugs.chromium.org/p/project-zero/issues/detail?id=1047) found by Gal Beniamini.

As we cannot legally distribute all files required for this test, a few steps need to be taken to make this work.

**Dumping BCM ROM**

Use [dhdutil](https://android.googlesource.com/platform/hardware/broadcom/wlan/+/master/bcmdhd/dhdutil) to dump the ROM on a device:

```
dhdutil -i wlan0 membytes -r 0x0 0x180000 > /data/local/tmp/bcm4358.rom.bin

```
**Obtain a copy of PatchRAM**

This is on the device already. On our Galaxy S6 used for testing, the file can be found in:

```
/system/etc/wifi/bcmdhd_sta.bin
```

Name this file bcm4358.patchram.bin.

**Obtain a ramdump**

Lastly, a live ramdump is required to make sure that wlc structures in memory have useful data. This should be obtained while WiFi is on and used.

```
dhdutil -i wlan0 coredump /data/local/tmp/ramdump.tmp
dd if=/data/local/tmp/ramdump.tmp of=/data/local/tmp/bcm4358.ramdump.bin bs=1 skip=$((0x146))
```

Finally with the files in the bcm4358 directory, run the example with ```./examples/bcm4358/qemu-bcm4358.sh```.

We tested this on a Samsung Galaxy S6, build MMB29K.G920FXXU4DPGU. The rom and patchram files have the following md5 sums:

```
0bf33ccf387d3d81dc7a07f2d5aa05fe  bcm4358.patchram.bin
570f33621459ffab3ddd9392c87a7b78  bcm4358.rom.bin
```
