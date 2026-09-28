# -*- coding: utf-8 -*-
"""Shared I/O + hashing helpers for the SN5 undub tooling.

WHY
---
Four scripts each grew their own copy of the same tiny helpers
(``HashSink``/``_HashSink``/``Sink``, ``sha_file``, ``extract_ram``).
They are byte-identical in behavior, so centralizing them here removes
duplication without changing any patch bytes or audit semantics.

Deliberately NOT shared: the voice-table loaders
(``build_v4.load_entries`` vs ``chapter_voice_census.load_table`` vs
``verify_shipped_patch.expect_entries``) and the MIPS cave generators.
The verifier re-derives those from documented semantics so a builder bug
cannot hide behind a shared helper (see verify_shipped_patch.py).
"""
import hashlib
import os
import struct

CHUNK = 1 << 22  # 4 MiB file-hash chunks


class HashSink(object):
    """Minimal write-only sink so ISO members can be hashed without extracting."""

    def __init__(self):
        self.h = hashlib.sha256()
        self.n = 0

    def write(self, b):
        self.h.update(b)
        self.n += len(b)
        return len(b)

    def tell(self):
        return self.n

    def hexdigest(self):
        return self.h.hexdigest()


def sha_file(path):
    """SHA-256 of a file, streamed in 4 MiB chunks."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(CHUNK), b''):
            h.update(b)
    return h.hexdigest()


def read_bytes(path):
    """Read a whole file as bytes (binary artifacts are small enough)."""
    with open(path, 'rb') as f:
        return f.read()


def hash_bytes(data):
    """SHA-256 hex digest of a bytes object."""
    return hashlib.sha256(data).hexdigest()


def member_hash(iso, path):
    """(sha256, size) of an ISO member via a streaming sink."""
    sink = HashSink()
    iso.get_file_from_iso_fp(sink, iso_path=path)
    return sink.hexdigest(), sink.n


def extract_ram_from_ppst(path):
    """Decompress a PPSSPP save state and return its raw RAM image.

    Single implementation shared by chapter_voice_census / loader_fixups /
    scan_all_blocks so the header layout lives in one place.

    Layout: 176-byte state header; first 16 bytes are
    (rev, comp, esize, usize); the zstd blob follows the header and
    decompresses to a chunk whose Memory section starts at 0x28
    (b'Memory', then +20 -> (memsize, ram...)). Raises ValueError on
    truncated/foreign states instead of asserting, so sweep-style batch
    tools can report EXTRACT FAIL and continue.
    """
    import zstandard
    with open(path, 'rb') as f:
        header = f.read(176)
        if len(header) < 176:
            raise ValueError('state too short: %r' % path)
        _rev, _comp, esize, usize = struct.unpack('<4I', header[:16])
        comp_blob = f.read(esize)
    if len(comp_blob) != esize:
        raise ValueError('truncated zstd blob in %r' % path)
    try:
        out = zstandard.ZstdDecompressor().decompress(
            comp_blob, max_output_size=usize + 16)
    except Exception as e:  # noqa: BLE001 - re-wrap with the path
        raise ValueError('zstd decode failed for %r: %s' % (path, e))
    if out[0x28:0x28 + 6] != b'Memory':
        raise ValueError('no Memory section in %r' % path)
    p1 = 0x28 + 20
    memsize = struct.unpack('<I', out[p1 + 8:p1 + 12])[0]
    return out[p1 + 12:p1 + 12 + memsize]


def find_states(state_dir, prefixes=('ULUS10656', 'NPJH50696')):
    """Sorted candidate .ppst paths in a PPSSPP_STATE directory."""
    if not state_dir or not os.path.isdir(state_dir):
        return []
    out = []
    for name in sorted(os.listdir(state_dir)):
        if not name.startswith(prefixes):
            continue
        if name.endswith('.ppst') or '.ppst.' in name:
            out.append(os.path.join(state_dir, name))
    return out
