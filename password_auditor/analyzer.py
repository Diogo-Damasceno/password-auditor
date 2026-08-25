"""Núcleo de análise de senhas: entropia, tempo de quebra, dicionário e reuso."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Iterable


_CHARSETS = [
    (r"[a-z]", 26),
    (r"[A-Z]", 26),
    (r"[0-9]", 10),
    (r"[^a-zA-Z0-9]", 33),
]


_COMMON = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "111111", "123123", "abc123", "senha", "iloveyou", "admin", "welcome",
    "monkey", "dragon", "letmein", "1q2w3e4r", "sunshine", "princess",
    "football", "000000", "picture1", "123321", "654321", "superman",
}


_SEQUENCES = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
    "abcdefghijklmnopqrstuvwxyz",
]


GUESSES_PER_SEC = {
    "online_throttled": 100,
    "online_unthrottled": 10_000,
    "offline_slow_hash": 10_000,
    "offline_fast_hash": 10_000_000_000,
}


@dataclass
class AuditResult:
    password_masked: str
    length: int
    charset_size: int
    entropy_bits: float
    crack_times: dict[str, str]
    is_common: bool
    has_sequence: bool
    reused_with: list[str] = field(default_factory=list)
    score: int = 0
    verdict: str = ""
    suggestions: list[str] = field(default_factory=list)


def _charset_size(password: str) -> int:
    size = 0
    for pattern, count in _CHARSETS:
        if re.search(pattern, password):
            size += count
    return size or 1


def shannon_entropy(password: str) -> float:
    """Entropia de Shannon baseada na distribuição real dos caracteres."""
    if not password:
        return 0.0
    freq: dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(password)
    return -sum((c / n) * math.log2(c / n) for c in freq.values()) * n


def search_space_entropy(password: str) -> float:
    """Entropia teórica: log2(charset_size ^ length)."""
    if not password:
        return 0.0
    return len(password) * math.log2(_charset_size(password))


def _has_sequence(password: str) -> bool:
    low = password.lower()
    for seq in _SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i:i + 3]
            if chunk in low or chunk[::-1] in low:
                return True

    if re.search(r"(.)\1\1", password):
        return True
    return False


def _human_time(seconds: float) -> str:
    if seconds < 1:
        return "instantâneo"
    units = [
        ("séculos", 60 * 60 * 24 * 365 * 100),
        ("anos", 60 * 60 * 24 * 365),
        ("dias", 60 * 60 * 24),
        ("horas", 60 * 60),
        ("minutos", 60),
        ("segundos", 1),
    ]
    for name, secs in units:
        if seconds >= secs:
            val = seconds / secs
            if val > 1e6:
                return f"{val:.2e} {name}"
            return f"{val:.1f} {name}"
    return "instantâneo"


def _crack_times(entropy_bits: float) -> dict[str, str]:

    guesses = 2 ** max(entropy_bits - 1, 0)
    out = {}
    for scenario, rate in GUESSES_PER_SEC.items():
        out[scenario] = _human_time(guesses / rate)
    return out


def _score(entropy_bits: float, is_common: bool, has_seq: bool) -> tuple[int, str]:
    if is_common:
        return 0, "Muito fraca (senha comum/vazada)"
    bits = entropy_bits
    if has_seq:
        bits *= 0.6
    if bits < 28:
        return 0, "Muito fraca"
    if bits < 36:
        return 1, "Fraca"
    if bits < 60:
        return 2, "Razoável"
    if bits < 128:
        return 3, "Forte"
    return 4, "Muito forte"


def _suggestions(password: str, res_common: bool, res_seq: bool, length: int,
                 charset_size: int) -> list[str]:
    tips: list[str] = []
    if res_common:
        tips.append("Evite senhas comuns/vazadas — esta aparece em wordlists.")
    if length < 12:
        tips.append("Use pelo menos 12–16 caracteres (comprimento importa mais que complexidade).")
    if charset_size < 62:
        tips.append("Misture maiúsculas, minúsculas, números e símbolos.")
    if res_seq:
        tips.append("Evite sequências de teclado (qwerty, 12345) e repetições.")
    if not tips:
        tips.append("Boa senha! Considere um gerenciador de senhas + 2FA.")
    tips.append("Prefira passphrases longas: 4–5 palavras aleatórias.")
    return tips


def _mask(password: str) -> str:
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def audit_password(password: str, others: Iterable[str] | None = None) -> AuditResult:
    """Audita uma senha e retorna um AuditResult completo."""
    others = list(others or [])
    charset = _charset_size(password)

    entropy = min(search_space_entropy(password), shannon_entropy(password) + 2 * len(password))
    is_common = password.lower() in _COMMON
    has_seq = _has_sequence(password)


    reused: list[str] = []
    ph = hashlib.sha256(password.encode()).hexdigest()
    for idx, o in enumerate(others):
        if hashlib.sha256(o.encode()).hexdigest() == ph:
            reused.append(f"conta #{idx + 1} ({_mask(o)})")

    crack = _crack_times(entropy)
    score, verdict = _score(entropy, is_common, has_seq)
    tips = _suggestions(password, is_common, has_seq, len(password), charset)

    return AuditResult(
        password_masked=_mask(password),
        length=len(password),
        charset_size=charset,
        entropy_bits=round(entropy, 1),
        crack_times=crack,
        is_common=is_common,
        has_sequence=has_seq,
        reused_with=reused,
        score=score,
        verdict=verdict,
        suggestions=tips,
    )
