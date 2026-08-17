# Original Introduction ( https://github.com/null-cell/ThinkPad-SVP-removal/ )

This repository serves as a upload location of my Masters Thesis and the reverse engineered and recreated exploit drivers taken from [this post](https://www.badcaps.net/forum/troubleshooting-hardware-devices-and-electronics-theory/troubleshooting-laptops-tablets-and-mobile-devices/bios-requests-only/78215-lenovo-bios-auto-patcher-for-supervisor-password-removal) of the badcaps forum. 
The original exploit drivers are assumed to have been created by [Victor Voinea](https://www.allservice.ro/).
The exploit replica drivers from this repository are re-built from the ground up and the drivers can be compiled as a part of the [EDKII build chain](https://github.com/tianocore/edk2).
The goal of my thesis and this repository repository was to understand how it is possible to remove the supervisor password and furthermore creating an open-source version of the exploit. 

# ThinkPad supervisor-password removal replica

Rebuilt DXE drivers and a patch pipeline for the physical-access supervisor
password (SVP) removal technique described in
[Bypassing_the_BIOS_supervisor_password_Mark_Juvan_s1085396.pdf](Bypassing_the_BIOS_supervisor_password_Mark_Juvan_s1085396.pdf).

Use this only on a machine you own or administer. An SPI write to the wrong
chip, at the wrong voltage, or with a bad image can leave the board unbootable.

## Layout

| Path | Purpose |
| --- | --- |
| `ExploitReplica.c` / `.inf` | `LenovoTranslateService` replacement driver |
| `ExploitReplicaBO.c` / `.inf` | `BootOption` replacement driver, performs the EC write |
| `build_ffs.sh` | builds both drivers in an edk2 checkout, emits `.ffs` files |
| `genWhole.sh` | packages one `.efi` as a DRIVER FFS |
| `tools/patch_bios.py` | injects the drivers and clears NVRAM in a dump |
| `tools/build_uefireplace.sh`, `tools/fetch_uefiextract.sh` | pinned helper tools |
| `tests/` | patcher unit tests (synthetic images only) |

## 1. Build the drivers


```sh
git clone https://github.com/tianocore/edk2.git
cd edk2
git checkout 2970e5699ba6267f3384ffab20f96647578aebc8
git submodule update --init --recursive
make -C BaseTools
cd ..
./build_ffs.sh edk2
```

Produces `BootOption.ffs` and `LenovoTranslateService.ffs` in this directory.

## 2. Fetch and build the patch tools

```sh
./tools/build_uefireplace.sh
./tools/fetch_uefiextract.sh
```

## 3. Dump the flash with an external programmer

Read the chip at least three times and accept a backup only if the reads agree:

```sh
sha256sum read_1.bin read_2.bin read_3.bin
cmp read_1.bin read_2.bin && cmp read_1.bin read_3.bin
cp --reflink=auto read_1.bin bios_original.bin && chmod a-w bios_original.bin
```

## 4. Patch

```sh
python3 tools/patch_bios.py bios_original.bin bios_patched.bin \
  --dxe BootOption.ffs \
  --dxe LenovoTranslateService.ffs \
  --clear-nvram \
  --uefi-replace tools/bin/UEFIReplace \
  --uefi-extract tools/bin/UEFIExtract
```

## 5. Boot and restore

1. Flash `bios_patched.bin` externally and verify the write against the file.
2. Boot. An empty NVRAM can cause several restart cycles before video appears.
3. Enter BIOS setup, type any character at the supervisor-password prompt.
4. At `SVP recovery is ready...`, press **`2`**. Any other key aborts without
   writing. Only offsets `0x00..0xF7` of EC bank `0x57` are written, then read
   back and reported.
5. When it prints `POWER OFF NOW`, remove power. The driver deliberately does
   not return, and you must not boot this image again.
6. Externally reflash and verify `bios_original.bin` before the next boot.
7. Confirm SVP is gone, load BIOS defaults, restore storage and protections,
   and set a new password.
