"""What kind of file is this? Two independent answers.

1. **Content-Type**: what the server (or uploader) *says* it is.
2. **Magic bytes**: what the first bytes *show* it is. Most file formats
   start with a fixed signature: Windows programs with `MZ`, ZIP archives
   with `PK\\x03\\x04`, PDFs with `%PDF-`.

They disagree more often than you'd think, by accident (a server that labels
everything `application/octet-stream`) or on purpose (malware served as
`text/plain`). The policy checks both, and blocks if *either* matches a
blocked type.

If the body is gzip/deflate-compressed (Content-Encoding), the magic bytes
belong to the compression, so the start of the body is decompressed first.
Brotli (`br`) isn't in Python's standard library; for it, only the
Content-Type is used.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass

SNIFF_BYTES = 512  # enough for every signature below

# (label, offset, signature). Checked in order.
MAGIC = [
    ("windows-executable", 0, b"MZ"),  # DOS/PE header: .exe, .dll, .sys, .scr
    ("linux-executable", 0, b"\x7fELF"),
    ("macos-executable", 0, b"\xcf\xfa\xed\xfe"),  # Mach-O 64-bit, little-endian
    ("macos-executable", 0, b"\xce\xfa\xed\xfe"),  # Mach-O 32-bit
    ("ole2", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),  # .msi, legacy .doc/.xls
    ("zip", 0, b"PK\x03\x04"),  # also .docx/.xlsx/.jar/.apk, which are ZIPs
    ("rar", 0, b"Rar!\x1a\x07"),
    ("7z", 0, b"7z\xbc\xaf\x27\x1c"),
    ("gzip", 0, b"\x1f\x8b"),
    ("pdf", 0, b"%PDF-"),
    ("png", 0, b"\x89PNG\r\n\x1a\n"),
    ("jpeg", 0, b"\xff\xd8\xff"),
    ("gif", 0, b"GIF87a"),
    ("gif", 0, b"GIF89a"),
    ("script", 0, b"#!"),  # shell/Python/Perl script with an interpreter line
]

CONTENT_TYPES = {
    "application/x-msdownload": "windows-executable",
    "application/x-dosexec": "windows-executable",
    "application/x-msdos-program": "windows-executable",
    "application/vnd.microsoft.portable-executable": "windows-executable",
    "application/x-executable": "linux-executable",
    "application/x-elf": "linux-executable",
    "application/x-sharedlib": "linux-executable",
    "application/x-mach-binary": "macos-executable",
    "application/x-msi": "ole2",
    "application/x-ms-installer": "ole2",
    "application/msword": "ole2",
    "application/vnd.ms-excel": "ole2",
    "application/zip": "zip",
    "application/x-zip-compressed": "zip",
    "application/vnd.rar": "rar",
    "application/x-rar-compressed": "rar",
    "application/x-7z-compressed": "7z",
    "application/gzip": "gzip",
    "application/x-gzip": "gzip",
    "application/pdf": "pdf",
    "image/png": "png",
    "image/jpeg": "jpeg",
    "image/gif": "gif",
    "application/x-sh": "script",
    "text/x-shellscript": "script",
}

KNOWN_TYPES = sorted({label for label, _, _ in MAGIC} | set(CONTENT_TYPES.values()))


@dataclass(frozen=True)
class FileType:
    by_magic: str | None  # from the first bytes
    by_content_type: str | None  # from the Content-Type header
    declared: str | None  # the Content-Type as sent, for the log and block page

    @property
    def label(self) -> str | None:
        """The best single answer: the bytes beat the label."""
        return self.by_magic or self.by_content_type

    @property
    def mismatch(self) -> bool:
        """Declared as one thing, but the bytes say another."""
        return bool(self.by_magic and self.declared and self.by_content_type != self.by_magic)

    def labels(self) -> set[str]:
        return {t for t in (self.by_magic, self.by_content_type) if t}


def media_type(content_type: str | None) -> str | None:
    """`text/html; charset=utf-8` -> `text/html`"""
    if not content_type:
        return None
    return content_type.split(";", 1)[0].strip().lower() or None


def sniff(data: bytes) -> str | None:
    for label, offset, signature in MAGIC:
        if data[offset : offset + len(signature)] == signature:
            return label
    return None


def decode_for_sniffing(data: bytes, content_encoding: str | None) -> bytes:
    """Undo gzip/deflate on the first bytes of a body (best effort)."""
    encoding = (content_encoding or "").strip().lower()
    if encoding not in ("gzip", "x-gzip", "deflate"):
        return data
    try:
        # wbits=47 accepts gzip and zlib headers; a truncated stream is fine.
        return zlib.decompressobj(wbits=47).decompress(data, SNIFF_BYTES)
    except zlib.error:
        try:
            return zlib.decompressobj(wbits=-15).decompress(data, SNIFF_BYTES)  # raw deflate
        except zlib.error:
            return data


def detect(content_type: str | None, first_bytes: bytes, content_encoding: str | None = None) -> FileType:
    declared = media_type(content_type)
    by_magic = sniff(decode_for_sniffing(first_bytes, content_encoding)) if first_bytes else None
    return FileType(by_magic=by_magic, by_content_type=CONTENT_TYPES.get(declared or ""), declared=declared)
