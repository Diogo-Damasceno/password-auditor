"""CLI do Password Auditor."""

from __future__ import annotations

import argparse
import getpass
import sys

from .analyzer import audit_password, AuditResult

_BARS = {0: "▁", 1: "▂▂", 2: "▃▃▃", 3: "▅▅▅▅", 4: "▇▇▇▇▇"}
_COLORS = {0: "\033[91m", 1: "\033[91m", 2: "\033[93m", 3: "\033[92m", 4: "\033[92m"}
_RESET = "\033[0m"


def _render(res: AuditResult, plain: bool = False) -> str:
    c = "" if plain else _COLORS.get(res.score, "")
    r = "" if plain else _RESET
    lines = [
        f"Senha:        {res.password_masked}",
        f"Comprimento:  {res.length}",
        f"Charset:      {res.charset_size} símbolos possíveis",
        f"Entropia:     {res.entropy_bits} bits",
        f"Força:        {c}{res.verdict} [{res.score}/4] {_BARS.get(res.score,'')}{r}",
    ]
    if res.is_common:
        lines.append("⚠  Senha encontrada em listas comuns/vazadas!")
    if res.has_sequence:
        lines.append("⚠  Contém sequência de teclado ou repetição.")
    if res.reused_with:
        lines.append(f"⚠  Reutilizada com: {', '.join(res.reused_with)}")
    lines.append("")
    lines.append("Tempo estimado para quebra:")
    labels = {
        "online_throttled": "  Online (limitado, 100/s):   ",
        "online_unthrottled": "  Online (sem limite, 10k/s): ",
        "offline_slow_hash": "  Offline (bcrypt):           ",
        "offline_fast_hash": "  Offline (MD5 em GPU):       ",
    }
    for k, label in labels.items():
        lines.append(f"{label}{res.crack_times[k]}")
    lines.append("")
    lines.append("Sugestões:")
    for tip in res.suggestions:
        lines.append(f"  • {tip}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audita a qualidade de senhas (não quebra senhas de terceiros)."
    )
    parser.add_argument("password", nargs="?", help="senha a analisar (omita para digitar oculto)")
    parser.add_argument("--plain", action="store_true", help="saída sem cores")
    parser.add_argument("--json", action="store_true", help="saída em JSON")
    args = parser.parse_args(argv)

    pwd = args.password or getpass.getpass("Senha (oculta): ")
    if not pwd:
        print("Nenhuma senha informada.", file=sys.stderr)
        return 1

    res = audit_password(pwd)

    if args.json:
        import json
        from dataclasses import asdict
        print(json.dumps(asdict(res), ensure_ascii=False, indent=2))
    else:
        print(_render(res, plain=args.plain))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
