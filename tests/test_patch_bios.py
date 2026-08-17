#!/usr/bin/env python3
import importlib.util
import struct
import unittest
import uuid
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "patch_bios.py"
SPEC = importlib.util.spec_from_file_location("patch_bios", MODULE_PATH)
patch_bios = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(patch_bios)


def make_section(section_type: int, body: bytes) -> bytes:
    size = 4 + len(body)
    section = size.to_bytes(3, "little") + bytes([section_type]) + body
    return section + b"\x00" * ((-len(section)) & 3)


def make_ffs(pe: bytes, ui: bytes = b"name") -> bytes:
    sections = (
        make_section(patch_bios.EFI_SECTION_DXE_DEPEX, b"\x06\x08")
        + make_section(patch_bios.EFI_SECTION_PE32, pe)
        + make_section(0x15, ui)
    )
    ffs = bytearray(24 + len(sections))
    ffs[:16] = bytes.fromhex("426c74e0f9d38b4fb2111410957b9ff5")
    ffs[18] = patch_bios.EFI_FV_FILETYPE_DRIVER
    ffs[19] = 0x40
    ffs[20:23] = len(ffs).to_bytes(3, "little")
    ffs[23] = 0xF8
    ffs[24:] = sections
    return bytes(ffs)


def write_fv(image: bytearray, off: int, size: int, filesystem_guid: bytes) -> None:
    header_size = 0x48
    image[off : off + 16] = b"\x00" * 16
    image[off + 16 : off + 32] = filesystem_guid
    struct.pack_into("<Q", image, off + 32, size)
    image[off + 40 : off + 44] = b"_FVH"
    struct.pack_into("<I", image, off + 44, patch_bios.EFI_FVB2_ERASE_POLARITY)
    struct.pack_into("<H", image, off + 48, header_size)
    struct.pack_into("<H", image, off + 50, 0)
    struct.pack_into("<H", image, off + 52, 0)
    image[off + 54] = 0
    image[off + 55] = 2
    struct.pack_into("<II", image, off + 56, size // 0x1000, 0x1000)
    struct.pack_into("<II", image, off + 64, 0, 0)
    words = struct.unpack_from(f"<{header_size // 2}H", image, off)
    struct.pack_into("<H", image, off + 50, (-sum(words)) & 0xFFFF)


def write_evsa_store(image: bytearray, off: int, size: int, attributes: int) -> None:
    header = bytearray(struct.pack("<BBH4sIII", 0xEC, 0, 20, b"EVSA", attributes, size, 0))
    header[1] = patch_bios.checksum8(header[2:])
    image[off : off + 20] = header

    entry = bytearray(22)
    entry[0] = 0xE1
    struct.pack_into("<H", entry, 2, len(entry))
    struct.pack_into("<H", entry, 4, 1)
    entry[6:22] = uuid.UUID("12345678-1234-5678-9abc-def012345678").bytes_le
    entry[1] = patch_bios.checksum8(entry[2:])
    image[off + 20 : off + 20 + len(entry)] = entry


def make_phoenix_evsa_image() -> tuple[bytearray, list[tuple[int, int]], tuple[int, int]]:
    image = bytearray([0xFF] * 0x100000)
    first_fv = (0x10000, 0x60000)
    second_fv = (0x70000, 0x29000)
    write_fv(image, *first_fv, patch_bios.EFI_SYSTEM_NV_DATA_FV_GUID)
    write_fv(image, *second_fv, patch_bios.PHOENIX_FPN_NV_STORAGE_FV_GUID)

    # An immutable defaults store must survive mutable-bank clearing.
    immutable = (0x16000, 0x2000)
    write_evsa_store(image, *immutable, 1)

    locations = {
        uuid.UUID("a27b1867-f105-4138-903f-164fde8f797e"): 0x20000,
        uuid.UUID("233d50b4-3343-43ea-bfd3-bab20ee154b3"): 0x30000,
        uuid.UUID("c22e6b8a-8159-49a3-b353-e84b79df19c0"): 0x40000,
        uuid.UUID("b6b5fab9-75c4-4aae-8314-7fffa7156eaa"): 0x52000,
        uuid.UUID("919b9699-8dd0-4376-aa0b-0e54cca47d8f"): 0x71000,
        uuid.UUID("58a90a52-929f-44f8-ac35-a7e1ab18ac91"): 0x85000,
    }
    body_ranges = []
    for guid, off in locations.items():
        _label, size, attributes, _fv_guid = patch_bios.PHOENIX_MUTABLE_EVSA[guid]
        write_evsa_store(image, off, size, attributes)
        body_ranges.append((off + patch_bios.PHOENIX_EVSA_HEADER_SIZE, off + size))

    physical_base = (1 << 32) - len(image)
    root_physical = physical_base
    entries = [
        (uuid.UUID(int=0), 0, 1, root_physical, 0x10000, 0),
        (
            uuid.UUID(bytes_le=patch_bios.EFI_SYSTEM_NV_DATA_FV_GUID),
            0,
            0xFE,
            physical_base + first_fv[0],
            first_fv[1],
            first_fv[0],
        ),
        (
            uuid.UUID(bytes_le=patch_bios.PHOENIX_FPN_NV_STORAGE_FV_GUID),
            0,
            0xFE,
            physical_base + second_fv[0],
            second_fv[1],
            second_fv[0],
        ),
    ]
    for guid, off in locations.items():
        _label, size, _attributes, _fv_guid = patch_bios.PHOENIX_MUTABLE_EVSA[guid]
        entries.append((guid, 1, 0xFE, physical_base + off, size, off))

    flash_map = 0x11000
    image[flash_map : flash_map + 10] = patch_bios.PHOENIX_FLASH_MAP_SIGNATURE
    struct.pack_into("<H", image, flash_map + 10, len(entries))
    struct.pack_into("<I", image, flash_map + 12, 0)
    for index, (guid, data_type, entry_type, physical, size, relative) in enumerate(entries):
        entry = flash_map + 16 + index * 36
        image[entry : entry + 16] = guid.bytes_le
        struct.pack_into(
            "<HHQII",
            image,
            entry + 16,
            data_type,
            entry_type,
            physical,
            size,
            relative,
        )
    return image, body_ranges, immutable


def make_nvram_fv(erase_polarity: bool) -> tuple[bytearray, int, int]:
    fv_size = 0x1000
    header_size = 0x48
    store_size = 0x100
    image = bytearray([0xFF if erase_polarity else 0x00] * fv_size)
    image[0:16] = b"\x00" * 16
    image[16:32] = patch_bios.EFI_SYSTEM_NV_DATA_FV_GUID
    struct.pack_into("<Q", image, 32, fv_size)
    image[40:44] = b"_FVH"
    attributes = patch_bios.EFI_FVB2_ERASE_POLARITY if erase_polarity else 0
    struct.pack_into("<I", image, 44, attributes)
    struct.pack_into("<H", image, 48, header_size)
    struct.pack_into("<H", image, 50, 0)
    struct.pack_into("<H", image, 52, 0)
    image[54] = 0
    image[55] = 2
    struct.pack_into("<II", image, 56, 1, fv_size)
    struct.pack_into("<II", image, 64, 0, 0)
    words = struct.unpack_from(f"<{header_size // 2}H", image, 0)
    struct.pack_into("<H", image, 50, (-sum(words)) & 0xFFFF)

    store = header_size
    image[store : store + 16] = patch_bios.EFI_AUTH_VARIABLE_STORE_GUID
    struct.pack_into("<I", image, store + 16, store_size)
    image[store + 20] = patch_bios.VARIABLE_STORE_FORMATTED
    image[store + 21] = patch_bios.VARIABLE_STORE_HEALTHY
    image[store + 22 : store + 28] = b"\x00" * 6
    image[store + 28 : store + store_size] = bytes(range(store_size - 28))
    image[store + store_size : store + store_size + 8] = b"PRESERVE"
    return image, store, store_size


class FfsLayoutTests(unittest.TestCase):
    def test_signature_ignores_pe_body_but_preserves_other_sections(self):
        first = patch_bios.ffs_non_pe_signature(make_ffs(b"first PE"), "first")
        second = patch_bios.ffs_non_pe_signature(make_ffs(b"different PE"), "second")
        changed_ui = patch_bios.ffs_non_pe_signature(
            make_ffs(b"different PE", b"other name"),
            "changed-ui",
        )

        self.assertEqual(first, second)
        self.assertNotEqual(first, changed_ui)


class NvramClearTests(unittest.TestCase):
    def test_clears_erase_polarity_true_and_preserves_headers(self):
        image, store, size = make_nvram_fv(True)
        fv_header = bytes(image[:0x48])
        store_header = bytes(image[store : store + 28])
        tail = bytes(image[store + size : store + size + 8])

        stores, changed = patch_bios.clear_nvram(image)

        self.assertEqual(stores, 1)
        self.assertGreater(changed, 0)
        self.assertEqual(bytes(image[:0x48]), fv_header)
        self.assertEqual(bytes(image[store : store + 28]), store_header)
        self.assertEqual(set(image[store + 28 : store + size]), {0xFF})
        self.assertEqual(bytes(image[store + size : store + size + 8]), tail)

    def test_uses_zero_for_erase_polarity_false(self):
        image, store, size = make_nvram_fv(False)
        stores, changed = patch_bios.clear_nvram(image)
        self.assertEqual(stores, 1)
        self.assertGreater(changed, 0)
        self.assertEqual(set(image[store + 28 : store + size]), {0x00})

    def test_refuses_unhealthy_store(self):
        image, store, _size = make_nvram_fv(True)
        image[store + 21] = 0x7F
        with self.assertRaises(SystemExit):
            patch_bios.clear_nvram(image)

    def test_clears_t450_phoenix_evsa_runtime_banks_only(self):
        image, body_ranges, immutable = make_phoenix_evsa_image()
        before = bytes(image)
        headers = [
            bytes(image[start - patch_bios.PHOENIX_EVSA_HEADER_SIZE : start])
            for start, _end in body_ranges
        ]

        stores, changed = patch_bios.clear_nvram(image)

        self.assertEqual(stores, 6)
        self.assertGreater(changed, 0)
        self.assertEqual(
            bytes(image[immutable[0] : immutable[0] + immutable[1]]),
            before[immutable[0] : immutable[0] + immutable[1]],
        )
        for index, (start, end) in enumerate(body_ranges):
            self.assertEqual(set(image[start:end]), {0xFF})
            self.assertEqual(
                bytes(image[start - patch_bios.PHOENIX_EVSA_HEADER_SIZE : start]),
                headers[index],
            )
        self.assertTrue(
            all(
                before[offset] == image[offset]
                for offset in range(len(image))
                if not any(start <= offset < end for start, end in body_ranges)
            )
        )

    def test_refuses_bad_phoenix_evsa_header_checksum(self):
        image, _body_ranges, _immutable = make_phoenix_evsa_image()
        image[0x20001] ^= 1
        with self.assertRaises(SystemExit):
            patch_bios.clear_nvram(image)


if __name__ == "__main__":
    unittest.main()
