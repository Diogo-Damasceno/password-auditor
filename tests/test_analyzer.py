import math

from password_auditor.analyzer import (
    audit_password,
    shannon_entropy,
    search_space_entropy,
    _has_sequence,
    _charset_size,
)


def test_common_password_is_flagged():
    res = audit_password("123456")
    assert res.is_common
    assert res.score == 0
    assert "comum" in res.verdict.lower() or res.score == 0


def test_strong_password_scores_high():
    res = audit_password("9x!Kq2@vLm7#Rp4Zt")
    assert res.score >= 3
    assert res.entropy_bits > 60


def test_charset_size():
    assert _charset_size("abc") == 26
    assert _charset_size("abcABC") == 52
    assert _charset_size("abcABC123") == 62
    assert _charset_size("abcABC123!") == 95


def test_sequence_detection():
    assert _has_sequence("qwerty")
    assert _has_sequence("aaa123")
    assert not _has_sequence("9x!Kq2@vL")


def test_entropy_monotonic_with_length():
    assert search_space_entropy("aaaa") < search_space_entropy("aaaaaaaa")


def test_shannon_entropy_zero_for_empty():
    assert shannon_entropy("") == 0.0


def test_reuse_detection():
    res = audit_password("hunter2", others=["hunter2", "outra"])
    assert res.reused_with  # detectou reuso


def test_crack_times_present():
    res = audit_password("Test123!")
    assert set(res.crack_times) == {
        "online_throttled",
        "online_unthrottled",
        "offline_slow_hash",
        "offline_fast_hash",
    }


def test_masking():
    res = audit_password("password")
    assert res.password_masked.startswith("p")
    assert res.password_masked.endswith("d")
    assert "*" in res.password_masked
