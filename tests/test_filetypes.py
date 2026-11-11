"""Phase 3: recognising file types by Content-Type and by magic bytes."""

import gzip
import zlib

import pytest

from swg import filetypes
from swg.caution import CautionTracker, add_token, split_token

EXE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 120 + b"This program cannot be run in DOS mode"


@pytest.mark.parametrize(
    "data, label",
    [
        (EXE, "windows-executable"),
        (b"\x7fELF\x02\x01\x01", "linux-executable"),
        (b"\xcf\xfa\xed\xfe\x07\x00", "macos-executable"),
        (b"PK\x03\x04\x14\x00", "zip"),
        (b"Rar!\x1a\x07\x01\x00", "rar"),
        (b"%PDF-1.7\n", "pdf"),
        (b"\x89PNG\r\n\x1a\n\x00", "png"),
        (b"#!/bin/sh\necho hi", "script"),
        (b"<!doctype html>", None),
    ],
)
def test_magic_bytes(data, label):
    assert filetypes.sniff(data) == label


def test_content_type_alone():
    file_type = filetypes.detect("application/x-msdownload", b"")
    assert file_type.by_content_type == "windows-executable" and file_type.by_magic is None


def test_bytes_beat_the_label():
    file_type = filetypes.detect("text/plain; charset=utf-8", EXE)
    assert file_type.label == "windows-executable"
    assert file_type.declared == "text/plain"
    assert file_type.mismatch  # declared text, actually a program


def test_generic_label_is_a_mismatch_too():
    assert filetypes.detect("application/octet-stream", EXE).mismatch


def test_matching_label_is_not_a_mismatch():
    assert not filetypes.detect("application/zip", b"PK\x03\x04").mismatch


@pytest.mark.parametrize("encoding, packed", [("gzip", gzip.compress(EXE)), ("deflate", zlib.compress(EXE))])
def test_compressed_bodies_are_unpacked_before_sniffing(encoding, packed):
    assert filetypes.sniff(packed) != "windows-executable"  # the raw bytes are gzip/zlib
    assert filetypes.detect("application/octet-stream", packed[:64], encoding).label == "windows-executable"


# ---- caution tokens -------------------------------------------------------------


def test_caution_token_round_trip():
    tracker = CautionTracker(accept_minutes=30)
    token = tracker.token("asha", "www.reddit.com")
    assert not tracker.accepted("asha", "www.reddit.com")
    assert tracker.accept("asha", "www.reddit.com", token)
    assert tracker.accepted("asha", "www.reddit.com")


def test_caution_token_cannot_be_reused_elsewhere():
    tracker = CautionTracker()
    token = tracker.token("asha", "www.reddit.com")
    assert not tracker.accept("dev", "www.reddit.com", token)  # another user
    assert not tracker.accept("asha", "chatgpt.com", token)  # another site
    expires, _, signature = token.partition(".")
    assert not tracker.accept("asha", "www.reddit.com", f"{int(expires) + 999999}.{signature}")  # edited
    assert not tracker.accept("asha", "www.reddit.com", f"1.{signature}")  # expired
    assert not CautionTracker().accept("asha", "www.reddit.com", token)  # another gateway's secret


def test_caution_acceptance_expires():
    tracker = CautionTracker(accept_minutes=0)
    assert tracker.accept("asha", "x.test", tracker.token("asha", "x.test"))
    assert not tracker.accepted("asha", "x.test")


def test_caution_parameter_is_added_and_removed():
    url = add_token("https://x.test/a?b=1", "T.S")
    assert url == "https://x.test/a?b=1&swg-caution=T.S"
    assert split_token("/a?b=1&swg-caution=T.S") == ("/a?b=1", "T.S")
    assert split_token("/a?swg-caution=T.S") == ("/a", "T.S")
    assert split_token("/a?b=1") == ("/a?b=1", None)
