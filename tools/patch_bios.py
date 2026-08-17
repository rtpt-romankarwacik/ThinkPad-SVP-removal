#!/usr/bin/env python3
"""Patch a verified Lenovo SPI/BIOS-region dump for temporary SVP recovery.

PE32-section replacement is delegated to UEFIReplace because the target files
are normally nested inside compressed firmware volumes.  The original FFS
metadata and non-PE sections are preserved.  NVRAM clearing is done in place
on the dump's own validated variable-storage volumes.  VSS/VSS2 and the
supported T450/T450s Phoenix EVSA runtime banks are emptied while preserving
FV/store headers, defaults, flash maps, FTW, and other model-specific data.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

EFI_SYSTEM_NV_DATA_FV_GUID = uuid.UUID("fff12b8d-7696-4c8b-a985-2747075b4f50").bytes_le
PHOENIX_FPN_NV_STORAGE_FV_GUID = uuid.UUID("00504624-8a59-4eeb-bd0f-6b36e96128e0").bytes_le
NVRAM_FV_GUIDS = (EFI_SYSTEM_NV_DATA_FV_GUID, PHOENIX_FPN_NV_STORAGE_FV_GUID)
EFI_AUTH_VARIABLE_STORE_GUID = uuid.UUID("aaf32c78-947b-439a-a180-2e144ec37792").bytes_le
EFI_VARIABLE_STORE_GUID = uuid.UUID("ddcf3616-3275-4164-98b6-fe85707ffe7d").bytes_le
EFI_FVB2_ERASE_POLARITY = 0x00000800
EFI_FV_FILETYPE_DRIVER = 0x07
EFI_FFS_ATTRIB_CHECKSUM = 0x40
FFS_FIXED_CHECKSUM = 0xAA
EFI_SECTION_PE32 = 0x10
EFI_SECTION_DXE_DEPEX = 0x13
BOOT_OPTION_FILE_GUID = uuid.UUID("e0746c42-d3f9-4f8b-b211-1410957b9ff5")
LENOVO_TRANSLATE_FILE_GUID = uuid.UUID("826bcf56-bac4-43f4-8ea1-8cdf0a121abd")
EMULATED_EEPROM_FILE_GUID = uuid.UUID("889004ee-8388-43be-8975-c593fc50bb4a")
EMULATED_EEPROM_PROTOCOL_GUID = uuid.UUID("82b244dc-8503-454b-a96a-d0d2e00bf86a")
VARIABLE_STORE_FORMATTED = 0x5A
VARIABLE_STORE_HEALTHY = 0xFE
EFI_IMAGE_MACHINE_X64 = 0x8664
EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11

PHOENIX_FLASH_MAP_SIGNATURE = b"_FLASH_MAP"
PHOENIX_FLASH_MAP_HEADER_SIZE = 16
PHOENIX_FLASH_MAP_ENTRY_SIZE = 36
PHOENIX_FLASH_MAP_MAX_ENTRIES = 113
PHOENIX_EVSA_SIGNATURE = b"EVSA"
PHOENIX_EVSA_HEADER_SIZE = 20
PHOENIX_EVSA_ENTRY_TYPES = {0xED, 0xEE, 0xEF, 0xE1, 0xE2, 0xE3, 0x83}
PHOENIX_EVSA_GUID_ENTRY_TYPES = {0xED, 0xE1}
PHOENIX_EVSA_NAME_ENTRY_TYPES = {0xEE, 0xE2}
PHOENIX_EVSA_DATA_ENTRY_TYPES = {0xEF, 0xE3, 0x83}
PHOENIX_EVSA_EXTENDED_HEADER = 0x10000000

# These six flash-map entries are the redundant mutable EVSA banks in the
# audited T450/T450s layout.  Their allocation size, owning FV, and current
# generation attribute are checked exactly; unknown Phoenix layouts are not
# guessed.  The earlier EVSA stores contain defaults, Secure Boot templates,
# and the Lenovo splash/public-key data and are deliberately preserved.
PHOENIX_MUTABLE_EVSA = {
    uuid.UUID("a27b1867-f105-4138-903f-164fde8f797e"): (
        "system-variable bank A",
        0x10000,
        0x00000007,
        EFI_SYSTEM_NV_DATA_FV_GUID,
    ),
    uuid.UUID("233d50b4-3343-43ea-bfd3-bab20ee154b3"): (
        "system-variable bank B",
        0x10000,
        0x00000006,
        EFI_SYSTEM_NV_DATA_FV_GUID,
    ),
    uuid.UUID("c22e6b8a-8159-49a3-b353-e84b79df19c0"): (
        "boot-variable bank A",
        0x12000,
        0x0000000A,
        EFI_SYSTEM_NV_DATA_FV_GUID,
    ),
    uuid.UUID("b6b5fab9-75c4-4aae-8314-7fffa7156eaa"): (
        "boot-variable bank B",
        0x12000,
        0x0000000B,
        EFI_SYSTEM_NV_DATA_FV_GUID,
    ),
    uuid.UUID("919b9699-8dd0-4376-aa0b-0e54cca47d8f"): (
        "security-variable bank A",
        0x14000,
        0x00000001,
        PHOENIX_FPN_NV_STORAGE_FV_GUID,
    ),
    uuid.UUID("58a90a52-929f-44f8-ac35-a7e1ab18ac91"): (
        "security-variable bank B",
        0x14000,
        0x00000000,
        PHOENIX_FPN_NV_STORAGE_FV_GUID,
    ),
}


def align4(value: int) -> int:
    return (value + 3) & ~3


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def ffs_size(buf: bytes | bytearray, off: int = 0) -> tuple[int, int]:
    if off < 0 or off + 24 > len(buf):
        raise ValueError("truncated FFS header")
    size = int.from_bytes(buf[off + 20 : off + 23], "little")
    if size != 0xFFFFFF:
        return size, 24
    if off + 32 > len(buf):
        raise ValueError("truncated extended FFS header")
    return struct.unpack_from("<Q", buf, off + 24)[0], 32


def validate_pe32(path: Path, pe_image: bytes) -> None:
    if len(pe_image) < 0x40 or pe_image[:2] != b"MZ":
        raise SystemExit(f"{path}: PE32 section is not a DOS/PE image")
    pe_off = struct.unpack_from("<I", pe_image, 0x3C)[0]
    if pe_off + 24 + 70 > len(pe_image) or pe_image[pe_off : pe_off + 4] != b"PE\0\0":
        raise SystemExit(f"{path}: invalid PE header")
    machine = struct.unpack_from("<H", pe_image, pe_off + 4)[0]
    optional = pe_off + 24
    magic = struct.unpack_from("<H", pe_image, optional)[0]
    subsystem = struct.unpack_from("<H", pe_image, optional + 68)[0]
    if machine != EFI_IMAGE_MACHINE_X64 or magic != 0x20B:
        raise SystemExit(f"{path}: PE32 section is not an X64 PE32+ image")
    if subsystem != EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
        raise SystemExit(
            f"{path}: PE subsystem {subsystem} is not EFI boot-service driver (11)"
        )


def validate_ffs(path: Path) -> tuple[uuid.UUID, bytes]:
    data = path.read_bytes()
    try:
        declared, header_size = ffs_size(data)
    except ValueError as exc:
        raise SystemExit(f"{path}: {exc}") from exc
    if declared != len(data):
        raise SystemExit(
            f"{path}: FFS declared size 0x{declared:x} does not equal file size 0x{len(data):x}"
        )
    if data[18] != EFI_FV_FILETYPE_DRIVER:
        raise SystemExit(f"{path}: expected DRIVER FFS type 0x07, got 0x{data[18]:02x}")
    if data[23] != 0x07:
        raise SystemExit(f"{path}: expected standalone FFS state 0x07, got 0x{data[23]:02x}")
    header = bytearray(data[:header_size])
    header[17] = 0
    header[23] = 0
    if sum(header) & 0xFF:
        raise SystemExit(f"{path}: invalid FFS header checksum")
    if data[19] & EFI_FFS_ATTRIB_CHECKSUM:
        if (sum(data[header_size:]) + data[17]) & 0xFF:
            raise SystemExit(f"{path}: invalid FFS data checksum")
    elif data[17] != FFS_FIXED_CHECKSUM:
        raise SystemExit(f"{path}: expected fixed FFS checksum 0xAA")

    pe_images: list[bytes] = []
    depex_sections: list[bytes] = []
    pos = header_size
    while pos + 4 <= declared:
        section_size = int.from_bytes(data[pos : pos + 3], "little")
        section_header = 4
        if section_size == 0xFFFFFF:
            if pos + 8 > declared:
                raise SystemExit(f"{path}: truncated extended section header at 0x{pos:x}")
            section_size = struct.unpack_from("<I", data, pos + 4)[0]
            section_header = 8
        if section_size < section_header or pos + section_size > declared:
            raise SystemExit(f"{path}: invalid section size at 0x{pos:x}")
        section_body = data[pos + section_header : pos + section_size]
        if data[pos + 3] == EFI_SECTION_PE32:
            pe_images.append(section_body)
        elif data[pos + 3] == EFI_SECTION_DXE_DEPEX:
            depex_sections.append(section_body)
        pos = align4(pos + section_size)

    if len(pe_images) != 1:
        raise SystemExit(f"{path}: expected exactly one PE32 section, found {len(pe_images)}")
    if depex_sections != [b"\x06\x08"]:
        raise SystemExit(f"{path}: expected one TRUE/END DXE DEPEX section")
    validate_pe32(path, pe_images[0])
    return uuid.UUID(bytes_le=data[:16]), pe_images[0]


def resolve_tool(requested: str | None, names: tuple[str, ...], purpose: str) -> Path:
    candidates: list[str] = []
    if requested:
        candidates.append(requested)
    else:
        candidates.extend(names)
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            path = Path(found).resolve()
            if os.access(path, os.X_OK):
                return path
        path = Path(candidate).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return path.resolve()
    requested_text = requested or "/".join(names)
    raise SystemExit(f"{purpose} not found or not executable: {requested_text}")


def run_uefi_replace(
    tool: Path,
    source: Path,
    destination: Path,
    replacement_pe: Path,
    label: str,
    guid: uuid.UUID,
) -> None:
    # Replace only the PE32 section body.  This preserves the dump's original
    # DEPEX, UI, version, Phoenix postcode section, and file attributes.
    command = [
        str(tool),
        str(source),
        str(guid),
        "10",
        str(replacement_pe),
        "-all",
        "-o",
        str(destination),
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output = result.stdout.strip()
    if output:
        for line in output.splitlines():
            print(f"  UEFIReplace: {line}")
    if result.returncode != 0:
        raise SystemExit(f"UEFIReplace failed for {label} with exit status {result.returncode}")
    if not destination.is_file():
        raise SystemExit(f"UEFIReplace reported success for {label} but produced no output")
    if destination.stat().st_size != source.stat().st_size:
        raise SystemExit(
            f"UEFIReplace changed image size for {label}: "
            f"{source.stat().st_size} -> {destination.stat().st_size}"
        )
    print(f"replaced the PE32 section for {label} ({guid}) through UEFIReplace")


def extract_pe_bodies(
    tool: Path,
    image: Path,
    guid: uuid.UUID,
    output_dir: Path,
    show_security_warnings: bool = False,
) -> list[bytes]:
    command = [
        str(tool),
        str(image),
        str(guid).upper(),
        "-o",
        str(output_dir),
        "-m",
        "body",
        "-t",
        "10",
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if show_security_warnings:
        important = {
            line.strip()
            for line in result.stdout.splitlines()
            if "hash mismatch" in line.lower() or "may refuse to boot" in line.lower()
        }
        for line in sorted(important):
            print(f"  UEFIExtract security warning ({image.name}): {line}")
    if result.returncode != 0:
        raise SystemExit(f"UEFIExtract could not find/parse PE32 section for {guid}")
    extracted = list(output_dir.rglob("body.bin")) if output_dir.exists() else []
    if not extracted:
        raise SystemExit(f"UEFIExtract returned success but extracted no PE32 section for {guid}")
    return [path.read_bytes() for path in extracted]


def ffs_non_pe_signature(data: bytes, label: str) -> tuple[int, int, int, tuple[tuple[int, bytes], ...]]:
    try:
        declared, header_size = ffs_size(data)
    except ValueError as exc:
        raise SystemExit(f"{label}: {exc}") from exc
    if declared != len(data):
        raise SystemExit(f"{label}: extracted FFS size is inconsistent")

    sections: list[tuple[int, bytes]] = []
    pos = header_size
    while pos + 4 <= declared:
        section_size = int.from_bytes(data[pos : pos + 3], "little")
        section_header = 4
        if section_size == 0xFFFFFF:
            if pos + 8 > declared:
                raise SystemExit(f"{label}: truncated extended section header")
            section_size = struct.unpack_from("<I", data, pos + 4)[0]
            section_header = 8
        if section_size < section_header or pos + section_size > declared:
            raise SystemExit(f"{label}: invalid section size at 0x{pos:x}")
        section_type = data[pos + 3]
        if section_type != EFI_SECTION_PE32:
            sections.append((section_type, data[pos : pos + section_size]))
        pos = align4(pos + section_size)

    return data[18], data[19], data[23], tuple(sections)


def extract_ffs_layouts(
    tool: Path,
    image: Path,
    guid: uuid.UUID,
    output_dir: Path,
) -> list[tuple[int, int, int, tuple[tuple[int, bytes], ...]]]:
    command = [
        str(tool),
        str(image),
        str(guid).upper(),
        "-o",
        str(output_dir),
        "-m",
        "file",
        "-t",
        "FF",
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        raise SystemExit(f"UEFIExtract could not extract the original FFS for {guid}")
    files = sorted(output_dir.rglob("*.ffs")) if output_dir.exists() else []
    if not files:
        raise SystemExit(f"UEFIExtract returned success but extracted no FFS for {guid}")
    signatures = [ffs_non_pe_signature(path.read_bytes(), str(path)) for path in files]
    return sorted(signatures)


def verify_emulated_eeprom(tool: Path, image: Path, work: Path) -> None:
    bodies = extract_pe_bodies(
        tool,
        image,
        EMULATED_EEPROM_FILE_GUID,
        work / "preflight-emulated-eeprom",
        show_security_warnings=True,
    )
    protocol = EMULATED_EEPROM_PROTOCOL_GUID.bytes_le
    matching = sum(protocol in body for body in bodies)
    if matching == 0:
        raise SystemExit("EmulatedEepromDxe does not contain the expected protocol GUID")
    hashes = ", ".join(sorted({sha256(body) for body in bodies}))
    print(
        f"preflight: {matching}/{len(bodies)} EmulatedEepromDxe PE32 instance(s) "
        f"contain protocol {EMULATED_EEPROM_PROTOCOL_GUID}; sha256 {hashes}"
    )


def verify_replaced_pe(
    tool: Path,
    image: Path,
    guid: uuid.UUID,
    expected_pe: bytes,
    work: Path,
    show_security_warnings: bool = False,
) -> None:
    extracted = extract_pe_bodies(
        tool,
        image,
        guid,
        work / f"verify-{guid}",
        show_security_warnings=show_security_warnings,
    )
    if any(body != expected_pe for body in extracted):
        raise SystemExit(f"post-patch PE32 verification failed for {guid}")
    print(
        f"verified {len(extracted)} extracted PE32 instance(s) for {guid}, "
        f"sha256 {sha256(expected_pe)}"
    )


def fv_header_checksum_valid(image: bytes | bytearray, off: int, header_len: int) -> bool:
    if header_len < 56 or header_len % 2 or off + header_len > len(image):
        return False
    words = struct.unpack_from(f"<{header_len // 2}H", image, off)
    return (sum(words) & 0xFFFF) == 0


def fv_block_map_valid(
    image: bytes | bytearray,
    off: int,
    header_len: int,
    fv_len: int,
) -> bool:
    total = 0
    pos = off + 56
    end = off + header_len
    while pos + 8 <= end:
        blocks, block_len = struct.unpack_from("<II", image, pos)
        pos += 8
        if blocks == 0 and block_len == 0:
            return total == fv_len
        if blocks == 0 or block_len == 0:
            return False
        total += blocks * block_len
        if total > fv_len:
            return False
    return False


def find_nvram_fvs(image: bytes | bytearray) -> list[tuple[int, int, int, int]]:
    volumes: set[tuple[int, int, int, int]] = set()
    for filesystem_guid in NVRAM_FV_GUIDS:
        pos = 0
        while True:
            guid_off = image.find(filesystem_guid, pos)
            if guid_off < 0:
                break
            fv_off = guid_off - 16
            pos = guid_off + 1
            if (
                fv_off < 0
                or fv_off + 56 > len(image)
                or image[fv_off + 40 : fv_off + 44] != b"_FVH"
            ):
                continue
            fv_len = struct.unpack_from("<Q", image, fv_off + 32)[0]
            attributes = struct.unpack_from("<I", image, fv_off + 44)[0]
            header_len = struct.unpack_from("<H", image, fv_off + 48)[0]
            if fv_len <= header_len or fv_off + fv_len > len(image):
                raise SystemExit(f"NVRAM FV at 0x{fv_off:x} has invalid bounds")
            if not fv_header_checksum_valid(image, fv_off, header_len):
                raise SystemExit(f"NVRAM FV at 0x{fv_off:x} has an invalid header checksum")
            if image[fv_off + 55] != 2:
                raise SystemExit(f"NVRAM FV at 0x{fv_off:x} has an unsupported revision")
            if not fv_block_map_valid(image, fv_off, header_len, fv_len):
                raise SystemExit(f"NVRAM FV at 0x{fv_off:x} has an invalid block map")
            volumes.add((fv_off, fv_len, attributes, header_len))
    return sorted(volumes)


def verify_nvram_preserved(original: bytes, staged: bytes | bytearray) -> None:
    original_volumes = find_nvram_fvs(original)
    staged_volumes = find_nvram_fvs(staged)
    if original_volumes != staged_volumes:
        raise SystemExit("UEFIReplace changed the NVRAM FV layout")
    for fv_off, fv_len, _attributes, _header_len in original_volumes:
        if original[fv_off : fv_off + fv_len] != staged[fv_off : fv_off + fv_len]:
            raise SystemExit(f"UEFIReplace unexpectedly changed NVRAM FV at 0x{fv_off:x}")
    if original_volumes:
        print(f"verified UEFIReplace preserved {len(original_volumes)} NVRAM FV(s) byte-for-byte")


def checksum8(data: bytes | bytearray) -> int:
    return (-sum(data)) & 0xFF


def find_phoenix_flash_maps(
    image: bytes | bytearray,
    volumes: list[tuple[int, int, int, int]],
) -> list[tuple[int, list[tuple[uuid.UUID, int, int, int, int, int]]]]:
    maps: list[tuple[int, list[tuple[uuid.UUID, int, int, int, int, int]]]] = []
    for fv_off, fv_len, _attributes, header_len in volumes:
        fv_end = fv_off + fv_len
        search = fv_off + header_len
        while True:
            map_off = image.find(PHOENIX_FLASH_MAP_SIGNATURE, search, fv_end)
            if map_off < 0:
                break
            search = map_off + 1
            if map_off + PHOENIX_FLASH_MAP_HEADER_SIZE > fv_end:
                continue
            count = struct.unpack_from("<H", image, map_off + 10)[0]
            reserved = struct.unpack_from("<I", image, map_off + 12)[0]
            map_size = PHOENIX_FLASH_MAP_HEADER_SIZE + count * PHOENIX_FLASH_MAP_ENTRY_SIZE
            if (
                count == 0
                or count > PHOENIX_FLASH_MAP_MAX_ENTRIES
                or reserved != 0
                or map_off + map_size > fv_end
            ):
                continue

            entries: list[tuple[uuid.UUID, int, int, int, int, int]] = []
            for index in range(count):
                entry_off = (
                    map_off
                    + PHOENIX_FLASH_MAP_HEADER_SIZE
                    + index * PHOENIX_FLASH_MAP_ENTRY_SIZE
                )
                guid = uuid.UUID(bytes_le=bytes(image[entry_off : entry_off + 16]))
                data_type, entry_type = struct.unpack_from("<HH", image, entry_off + 16)
                physical, size, relative = struct.unpack_from("<QII", image, entry_off + 20)
                entries.append((guid, data_type, entry_type, physical, size, relative))
            maps.append((map_off, entries))
    return maps


def containing_nvram_fv(
    image: bytes | bytearray,
    volumes: list[tuple[int, int, int, int]],
    off: int,
    size: int,
) -> tuple[int, int, int, int, bytes]:
    matches = [
        volume
        for volume in volumes
        if volume[0] <= off and off + size <= volume[0] + volume[1]
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"Phoenix EVSA allocation at 0x{off:x} is not inside exactly one NVRAM FV"
        )
    fv_off, fv_len, attributes, header_len = matches[0]
    return fv_off, fv_len, attributes, header_len, bytes(image[fv_off + 16 : fv_off + 32])


def validate_phoenix_evsa_store(
    image: bytes | bytearray,
    off: int,
    allocation_size: int,
    expected_attributes: int,
    empty_byte: int,
    label: str,
    require_empty: bool = False,
) -> int:
    end = off + allocation_size
    if off < 0 or allocation_size < PHOENIX_EVSA_HEADER_SIZE or end > len(image):
        raise SystemExit(f"{label} has invalid bounds")
    entry_type, stored_checksum, header_size = struct.unpack_from("<BBH", image, off)
    attributes, store_size, reserved = struct.unpack_from("<III", image, off + 8)
    if entry_type != 0xEC or image[off + 4 : off + 8] != PHOENIX_EVSA_SIGNATURE:
        raise SystemExit(f"{label} at 0x{off:x} has an invalid EVSA signature/type")
    if header_size != PHOENIX_EVSA_HEADER_SIZE or store_size != allocation_size:
        raise SystemExit(f"{label} at 0x{off:x} has an unexpected header/store size")
    if attributes != expected_attributes or reserved != 0:
        raise SystemExit(
            f"{label} at 0x{off:x} has unexpected attributes/reserved fields "
            f"(0x{attributes:08x}, 0x{reserved:08x})"
        )
    calculated = checksum8(image[off + 2 : off + header_size])
    if stored_checksum != calculated:
        raise SystemExit(
            f"{label} at 0x{off:x} has an invalid header checksum "
            f"(0x{stored_checksum:02x}, expected 0x{calculated:02x})"
        )

    entry_count = 0
    pos = off + header_size
    while pos < end:
        if image[pos] == empty_byte:
            if any(value != empty_byte for value in image[pos:end]):
                raise SystemExit(f"{label} at 0x{off:x} has non-erased bytes after its terminator")
            if require_empty and pos != off + header_size:
                raise SystemExit(f"{label} at 0x{off:x} was not emptied")
            return entry_count
        current_type = image[pos]
        if current_type not in PHOENIX_EVSA_ENTRY_TYPES or pos + 4 > end:
            raise SystemExit(f"{label} at 0x{off:x} has an unsupported EVSA entry at 0x{pos:x}")
        current_checksum = image[pos + 1]
        entry_size = struct.unpack_from("<H", image, pos + 2)[0]
        if entry_size < 4 or pos + entry_size > end:
            raise SystemExit(f"{label} at 0x{off:x} has an invalid EVSA entry size")
        calculated = checksum8(image[pos + 2 : pos + entry_size])
        if current_checksum != calculated:
            raise SystemExit(
                f"{label} at 0x{off:x} has an invalid entry checksum at 0x{pos:x}"
            )
        if current_type in PHOENIX_EVSA_GUID_ENTRY_TYPES and entry_size != 22:
            raise SystemExit(f"{label} at 0x{off:x} has an invalid GUID entry")
        if current_type in PHOENIX_EVSA_NAME_ENTRY_TYPES:
            if (
                entry_size < 8
                or (entry_size - 6) % 2
                or image[pos + entry_size - 2 : pos + entry_size] != b"\0\0"
            ):
                raise SystemExit(f"{label} at 0x{off:x} has an invalid name entry")
        if current_type in PHOENIX_EVSA_DATA_ENTRY_TYPES:
            if entry_size < 12:
                raise SystemExit(f"{label} at 0x{off:x} has a truncated data entry")
            variable_attributes = struct.unpack_from("<I", image, pos + 8)[0]
            if variable_attributes & PHOENIX_EVSA_EXTENDED_HEADER:
                raise SystemExit(f"{label} at 0x{off:x} uses unsupported extended EVSA data")
        entry_count += 1
        pos += entry_size
    raise SystemExit(f"{label} at 0x{off:x} has no erased terminator/free space")


def clear_phoenix_evsa(
    image: bytearray,
    volumes: list[tuple[int, int, int, int]],
) -> tuple[int, int]:
    matching_maps: list[
        tuple[int, list[tuple[uuid.UUID, int, int, int, int, int]]]
    ] = []
    target_guids = set(PHOENIX_MUTABLE_EVSA)
    for map_off, entries in find_phoenix_flash_maps(image, volumes):
        present = {entry[0] for entry in entries} & target_guids
        if not present:
            continue
        if present != target_guids:
            missing = ", ".join(str(guid) for guid in sorted(target_guids - present, key=str))
            raise SystemExit(
                f"Phoenix flash map at 0x{map_off:x} has only part of the "
                f"supported EVSA layout; missing {missing}"
            )
        matching_maps.append((map_off, entries))
    if not matching_maps:
        return 0, 0
    if len(matching_maps) != 1:
        raise SystemExit("multiple Phoenix flash maps contain the supported mutable EVSA layout")

    map_off, entries = matching_maps[0]
    by_guid: dict[uuid.UUID, tuple[uuid.UUID, int, int, int, int, int]] = {}
    for entry in entries:
        if entry[0] not in target_guids:
            continue
        if entry[0] in by_guid:
            raise SystemExit(
                f"Phoenix flash map at 0x{map_off:x} contains duplicate GUID {entry[0]}"
            )
        by_guid[entry[0]] = entry

    root_entries = [entry for entry in entries if entry[1] == 0 and entry[2] == 1]
    if len(root_entries) != 1:
        raise SystemExit(f"Phoenix flash map at 0x{map_off:x} has no unique root volume")
    root_physical = root_entries[0][3]
    physical_image_base = (1 << 32) - len(image)
    if physical_image_base < 0 or root_physical < physical_image_base:
        raise SystemExit("Phoenix flash-map physical addresses do not map to this image size")

    # Require the map to describe both actual NVRAM FV headers exactly.
    for fv_off, fv_len, _attributes, _header_len in volumes:
        filesystem_guid = uuid.UUID(bytes_le=bytes(image[fv_off + 16 : fv_off + 32]))
        expected_physical = physical_image_base + fv_off
        candidates = [
            entry
            for entry in entries
            if entry[0] == filesystem_guid
            and entry[1] == 0
            and entry[3] == expected_physical
            and entry[4] == fv_len
        ]
        if len(candidates) != 1:
            raise SystemExit(
                f"Phoenix flash map does not describe NVRAM FV {filesystem_guid} at 0x{fv_off:x}"
            )

    before = bytes(image)
    body_ranges: list[tuple[int, int, int]] = []
    store_count = 0
    changed_count = 0
    for guid, (
        label,
        expected_size,
        expected_attributes,
        expected_fv_guid,
    ) in PHOENIX_MUTABLE_EVSA.items():
        _guid, data_type, entry_type, physical, allocation_size, relative = by_guid[guid]
        if data_type != 1 or entry_type != 0xFE or allocation_size != expected_size:
            raise SystemExit(f"Phoenix flash-map entry {guid} has an unexpected type or size")
        if physical < physical_image_base or physical + allocation_size > (1 << 32):
            raise SystemExit(f"Phoenix flash-map entry {guid} is outside the supplied image")
        if relative != physical - root_physical:
            raise SystemExit(f"Phoenix flash-map entry {guid} has an inconsistent relative offset")
        store_off = physical - physical_image_base
        _fv_off, _fv_len, fv_attributes, _header_len, filesystem_guid = containing_nvram_fv(
            image, volumes, store_off, allocation_size
        )
        if filesystem_guid != expected_fv_guid:
            raise SystemExit(f"{label} is in the wrong NVRAM FV")
        empty_byte = 0xFF if fv_attributes & EFI_FVB2_ERASE_POLARITY else 0x00
        entries_before = validate_phoenix_evsa_store(
            image,
            store_off,
            allocation_size,
            expected_attributes,
            empty_byte,
            label,
        )
        body_off = store_off + PHOENIX_EVSA_HEADER_SIZE
        changed = sum(
            value != empty_byte for value in image[body_off : store_off + allocation_size]
        )
        image[body_off : store_off + allocation_size] = bytes([empty_byte]) * (
            allocation_size - PHOENIX_EVSA_HEADER_SIZE
        )
        validate_phoenix_evsa_store(
            image,
            store_off,
            allocation_size,
            expected_attributes,
            empty_byte,
            label,
            require_empty=True,
        )
        body_ranges.append((body_off, store_off + allocation_size, empty_byte))
        store_count += 1
        changed_count += changed
        print(
            f"  cleared Phoenix EVSA {label} at 0x{store_off:x}, size 0x{allocation_size:x}; "
            f"removed {entries_before} entry record(s), changed {changed} byte(s)"
        )

    expected = bytearray(before)
    for body_off, body_end, empty_byte in body_ranges:
        expected[body_off:body_end] = bytes([empty_byte]) * (body_end - body_off)
    if image != expected:
        raise SystemExit("internal error: Phoenix EVSA clearing changed bytes outside store bodies")
    return store_count, changed_count


def clear_nvram(image: bytearray) -> tuple[int, int]:
    volumes = find_nvram_fvs(image)
    store_count = 0
    changed_count = 0
    for fv_off, fv_len, attributes, header_len in volumes:
        empty_byte = 0xFF if attributes & EFI_FVB2_ERASE_POLARITY else 0x00
        print(
            f"found NVRAM FV at 0x{fv_off:x}, length 0x{fv_len:x}, "
            f"erase byte 0x{empty_byte:02x}"
        )
        fv_end = fv_off + fv_len
        search = fv_off + header_len
        while search < fv_end:
            candidates = []
            for store_guid in (EFI_AUTH_VARIABLE_STORE_GUID, EFI_VARIABLE_STORE_GUID):
                idx = image.find(store_guid, search, fv_end)
                if idx >= 0:
                    candidates.append((idx, store_guid))
            if not candidates:
                break
            store_off, store_guid = min(candidates)
            if store_off + 28 > fv_end:
                search = store_off + 1
                continue
            store_size = struct.unpack_from("<I", image, store_off + 16)[0]
            fmt = image[store_off + 20]
            state = image[store_off + 21]
            if store_size < 28 or store_off + store_size > fv_end:
                search = store_off + 1
                continue
            if fmt != VARIABLE_STORE_FORMATTED or state != VARIABLE_STORE_HEALTHY:
                raise SystemExit(
                    f"variable store at 0x{store_off:x} is not healthy/formatted "
                    f"(format 0x{fmt:02x}, state 0x{state:02x})"
                )
            if store_off % 4 or any(image[store_off + 22 : store_off + 28]):
                raise SystemExit(f"variable store at 0x{store_off:x} has invalid reserved/alignment fields")

            body_off = store_off + 28
            old_body = image[body_off : store_off + store_size]
            changed = sum(value != empty_byte for value in old_body)
            image[body_off : store_off + store_size] = bytes([empty_byte]) * (store_size - 28)
            store_count += 1
            changed_count += changed
            print(
                f"  cleared variable store {uuid.UUID(bytes_le=store_guid)} at 0x{store_off:x}, "
                f"size 0x{store_size:x}; changed {changed} byte(s)"
            )
            search = store_off + store_size

    evsa_stores, evsa_changed = clear_phoenix_evsa(image, volumes)
    store_count += evsa_stores
    changed_count += evsa_changed

    if not volumes:
        raise SystemExit("no valid supported NVRAM firmware volume found")
    if store_count == 0:
        raise SystemExit("found NVRAM FV(s), but no supported variable-store layout was found")
    return store_count, changed_count


def validate_dump_size(path: Path, allow_nonstandard: bool) -> None:
    size = path.stat().st_size
    if path.suffix.lower() in {".fl1", ".fl2"} and not allow_nonstandard:
        raise SystemExit(
            f"{path}: Lenovo FL1/FL2 files are vendor updates, not external-programmer dumps"
        )
    if size < 1024 * 1024:
        raise SystemExit(f"{path}: image is implausibly small ({size} bytes)")
    if size % 4096 and not allow_nonstandard:
        raise SystemExit(
            f"{path}: size {size} is not 4 KiB aligned; this looks like a vendor update/capsule, "
            "not an external-programmer dump. Use the actual SPI/BIOS-region dump. "
            "Pass --allow-nonstandard-size only for offline testing."
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Patch a verified Lenovo SPI/BIOS dump using UEFIReplace and clear "
            "its own supported NVRAM stores"
        )
    )
    parser.add_argument("input", type=Path, help="untouched external-programmer SPI/BIOS-region dump")
    parser.add_argument("output", type=Path, help="patched output path")
    parser.add_argument("--dxe", type=Path, action="append", default=[], help="driver FFS to replace; repeat for each driver")
    parser.add_argument("--uefi-replace", help="path to legacy UEFIReplace (defaults to PATH)")
    parser.add_argument("--uefi-extract", help="path to UEFIExtract NE for post-patch PE verification")
    parser.add_argument(
        "--clear-nvram",
        action="store_true",
        help="empty supported VSS/VSS2 or validated T450/T450s Phoenix EVSA runtime-store bodies",
    )
    parser.add_argument("--allow-nonstandard-size", action="store_true", help="allow non-4-KiB-aligned input for offline tests only")
    parser.add_argument("--force", action="store_true", help="overwrite an existing output file")
    args = parser.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"input not found: {args.input}")
    if not args.dxe and not args.clear_nvram:
        raise SystemExit("nothing requested: pass --dxe and/or --clear-nvram")
    if args.dxe and not args.clear_nvram:
        raise SystemExit("DXE patching requires --clear-nvram for this recovery technique")
    if args.dxe and not args.uefi_extract:
        raise SystemExit("DXE patching requires --uefi-extract for preflight/post-patch verification")
    if args.input.resolve() == args.output.resolve() or (
        args.output.exists() and os.path.samefile(args.input, args.output)
    ):
        raise SystemExit("input and output must be different files")
    if args.output.exists() and not args.force:
        raise SystemExit(f"output already exists: {args.output} (use --force to overwrite)")
    validate_dump_size(args.input, args.allow_nonstandard_size)

    drivers: list[tuple[Path, uuid.UUID, bytes]] = []
    seen_guids: set[uuid.UUID] = set()
    for ffs_path in args.dxe:
        if not ffs_path.is_file():
            raise SystemExit(f"FFS file not found: {ffs_path}")
        guid, pe = validate_ffs(ffs_path)
        if guid in seen_guids:
            raise SystemExit(f"duplicate --dxe GUID: {guid}")
        seen_guids.add(guid)
        drivers.append((ffs_path.resolve(), guid, pe))
    if drivers and seen_guids != {BOOT_OPTION_FILE_GUID, LENOVO_TRANSLATE_FILE_GUID}:
        raise SystemExit(
            "DXE patching requires exactly BootOption.ffs and LenovoTranslateService.ffs"
        )
    # BootOption is much smaller than Lenovo's original file and creates the
    # free space needed by the larger rebuilt LenovoTranslateService file.
    drivers.sort(key=lambda item: 0 if item[1] == BOOT_OPTION_FILE_GUID else 1)

    replace_tool = None
    extract_tool = None
    if drivers:
        replace_tool = resolve_tool(args.uefi_replace, ("UEFIReplace", "uefireplace"), "UEFIReplace")
        extract_tool = resolve_tool(
            args.uefi_extract,
            ("UEFIExtract", "uefiextract"),
            "UEFIExtract",
        )

    original = args.input.read_bytes()
    print(f"input: {args.input} ({len(original)} bytes), sha256 {sha256(original)}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="svp-patch-") as tmp_name:
        work = Path(tmp_name)
        current = work / "stage-0.bin"
        current.write_bytes(original)

        original_ffs_layouts: dict[
            uuid.UUID,
            list[tuple[int, int, int, tuple[tuple[int, bytes], ...]]],
        ] = {}
        if extract_tool is not None:
            verify_emulated_eeprom(extract_tool, current, work)
            for _ffs_path, guid, _pe in drivers:
                original_ffs_layouts[guid] = extract_ffs_layouts(
                    extract_tool,
                    current,
                    guid,
                    work / f"preflight-ffs-{guid}",
                )

        assert replace_tool is not None or not drivers
        for index, (ffs_path, guid, pe) in enumerate(drivers, start=1):
            next_stage = work / f"stage-{index}.bin"
            replacement_pe = work / f"replacement-{index}.efi"
            replacement_pe.write_bytes(pe)
            run_uefi_replace(
                replace_tool,
                current,
                next_stage,
                replacement_pe,
                ffs_path.name,
                guid,
            )
            current = next_stage

        image = bytearray(current.read_bytes())
        if drivers:
            verify_nvram_preserved(original, image)
        if args.clear_nvram:
            stores, changed = clear_nvram(image)
            print(f"NVRAM: cleared {stores} store(s), changed {changed} byte(s)")
            if changed == 0:
                print("warning: the NVRAM variable-store body was already empty")
        current.write_bytes(image)

        if extract_tool is not None:
            for index, (_ffs_path, guid, expected_pe) in enumerate(drivers):
                verify_replaced_pe(
                    extract_tool,
                    current,
                    guid,
                    expected_pe,
                    work,
                    show_security_warnings=index == 0,
                )
                final_layouts = extract_ffs_layouts(
                    extract_tool,
                    current,
                    guid,
                    work / f"verify-ffs-{guid}",
                )
                if final_layouts != original_ffs_layouts[guid]:
                    raise SystemExit(f"non-PE FFS metadata/section verification failed for {guid}")
                print(f"verified preserved non-PE FFS sections for {guid}")

        if len(image) != len(original):
            raise SystemExit(f"internal error: output size changed ({len(original)} -> {len(image)})")
        output_hash = sha256(image)
        if bytes(image) == original:
            print("warning: requested operations made no byte changes")

        temp_output = args.output.with_name(f".{args.output.name}.tmp-{os.getpid()}")
        try:
            with temp_output.open("wb") as output_file:
                output_file.write(image)
                output_file.flush()
                os.fsync(output_file.fileno())
            os.replace(temp_output, args.output)
        finally:
            if temp_output.exists():
                temp_output.unlink()

    print(f"output: {args.output} ({args.output.stat().st_size} bytes), sha256 {output_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
