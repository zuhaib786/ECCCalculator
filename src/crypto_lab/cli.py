"""Unified command-line lessons for the educational cryptography toolkit."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence

from ecc_factor import FactorizationError, FactorizationEvent, factorize

from . import EDUCATIONAL_WARNING
from .encoding import bytes_to_int, split_blocks
from .feistel import ToyFeistelCipher
from .number_theory import mod_pow
from .primality import check_primality
from .rsa import RSAKeyPair
from .trace import TraceEvent
from .course_cli import COURSE_RUNNERS, register_course_commands


def _integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not an integer: {value}") from error


def _integer_at_least_two(value: str) -> int:
    parsed = _integer(value)
    if parsed < 2:
        raise argparse.ArgumentTypeError("value must be at least 2")
    return parsed


def _positive_integer(value: str) -> int:
    parsed = _integer(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _hex_bytes(value: str, *, length: int, label: str) -> bytes:
    try:
        parsed = bytes.fromhex(value.removeprefix("0x"))
    except ValueError as error:
        raise ValueError(f"{label} must be hexadecimal") from error
    if len(parsed) != length:
        raise ValueError(f"{label} must encode exactly {length} bytes")
    return parsed


def _add_output_options(parser: argparse.ArgumentParser, *, quiet: bool = False) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="show teaching stages; repeat for individual rounds/steps",
    )
    if quiet:
        group.add_argument("-q", "--quiet", action="store_true", help="result only")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crypto-lab",
        description="Inspect the mechanics taught in an introductory cryptography class.",
        epilog=EDUCATIONAL_WARNING,
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.4.0")
    commands = parser.add_subparsers(dest="command", required=True)

    factor = commands.add_parser("factor", help="factor an integer")
    factor.add_argument("number", type=_integer_at_least_two)
    factor.add_argument(
        "-m",
        "--method",
        choices=("auto", "trial", "rho", "ecm", "cfrac"),
        default="auto",
    )
    factor.add_argument("--seed", type=int)
    factor.add_argument("--ecm-bound", type=int, default=2_000)
    factor.add_argument("--ecm-curves", type=int, default=50)
    factor.add_argument("--cfrac-bound", type=int, default=100)
    factor.add_argument("--cfrac-steps", type=int, default=10_000)
    _add_output_options(factor, quiet=True)

    prime = commands.add_parser("prime", help="compare classroom primality tests")
    prime.add_argument("number", type=_integer)
    prime.add_argument(
        "--test",
        choices=("trial", "fermat", "miller-rabin", "solovay-strassen"),
        default="miller-rabin",
    )
    prime.add_argument("--rounds", type=_positive_integer, default=8)
    prime.add_argument("--seed", type=int)
    prime.add_argument(
        "--base",
        type=_integer,
        action="append",
        dest="bases",
        help="use an explicit test base; may be repeated",
    )
    _add_output_options(prime)

    encode = commands.add_parser("encode", help="inspect UTF-8, hex, integers, and blocks")
    encode.add_argument("text")
    encode.add_argument("--encoding", default="utf-8")
    encode.add_argument("--block-size", type=_positive_integer, default=4)
    _add_output_options(encode)

    power = commands.add_parser("modpow", help="show square-and-multiply modular exponentiation")
    power.add_argument("base", type=_integer)
    power.add_argument("exponent", type=_integer)
    power.add_argument("modulus", type=_integer)
    _add_output_options(power)

    rsa = commands.add_parser("rsa-demo", help="encode, encrypt, decrypt, and decode with textbook RSA")
    rsa.add_argument("text")
    rsa.add_argument("--p", type=_integer_at_least_two, default=3557)
    rsa.add_argument("--q", type=_integer_at_least_two, default=2579)
    rsa.add_argument("-e", type=_integer_at_least_two, default=65_537)
    _add_output_options(rsa)

    feistel = commands.add_parser("feistel-demo", help="inspect a toy Feistel block cipher")
    feistel.add_argument("text")
    feistel.add_argument("--key", type=_integer, default=0x1334_5779_9BBC_DFF1)
    feistel.add_argument("--rounds", type=int, default=8)
    feistel.add_argument("--mode", choices=("ecb", "cbc"), default="cbc")
    feistel.add_argument("--iv", default="0001020304050607", help="8-byte CBC IV in hex")
    _add_output_options(feistel)
    register_course_commands(commands)
    return parser


def _trace_printer(verbosity: int):
    def report(event: TraceEvent | FactorizationEvent) -> None:
        if verbosity >= event.level:
            print(f"[{event.code}] {event.message}", file=sys.stderr)

    return report


def _run_factor(args: argparse.Namespace) -> int:
    callback = _trace_printer(args.verbose) if args.verbose else None
    factors = factorize(
        args.number,
        method=args.method,
        seed=args.seed,
        progress=callback,
        ecm_bound=args.ecm_bound,
        ecm_curves=args.ecm_curves,
        cfrac_bound=args.cfrac_bound,
        cfrac_steps=args.cfrac_steps,
    )
    if args.json:
        print(json.dumps({"number": args.number, "factors": list(factors), "method": args.method}, sort_keys=True))
    elif args.quiet:
        print(" ".join(map(str, factors)))
    else:
        counts = Counter(factors)
        terms = [str(prime) if count == 1 else f"{prime}^{count}" for prime, count in counts.items()]
        print(f"{args.number} = {' * '.join(terms)}")
    return 0


def _run_prime(args: argparse.Namespace) -> int:
    callback = _trace_printer(args.verbose) if args.verbose else None
    result = check_primality(
        args.number,
        method=args.test,
        rounds=args.rounds,
        seed=args.seed,
        bases=args.bases,
        trace=callback,
    )
    payload = {
        "number": result.number,
        "test": result.method,
        "probably_prime": result.probably_prime,
        "deterministic": result.deterministic,
        "bases": list(result.bases),
        "witness": result.witness,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        verdict = "prime" if result.probably_prime and result.deterministic else (
            "probably prime" if result.probably_prime else "composite"
        )
        qualifier = "deterministic" if result.deterministic else "probabilistic"
        print(f"{result.number}: {verdict} ({result.method}, {qualifier})")
        if result.witness is not None:
            print(f"witness: {result.witness}")
    return 0


def _run_encode(args: argparse.Namespace) -> int:
    encoded = args.text.encode(args.encoding)
    blocks = split_blocks(encoded, args.block_size)
    result = {
        "text": args.text,
        "encoding": args.encoding,
        "byte_length": len(encoded),
        "hex": encoded.hex(),
        "integer": bytes_to_int(encoded),
        "blocks": [
            {"hex": block.hex(), "integer": bytes_to_int(block)} for block in blocks
        ],
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"text:    {args.text}")
        print(f"bytes:   {encoded!r}")
        print(f"hex:     {result['hex']}")
        print(f"integer: {result['integer']}")
        items = ", ".join(
            f"{item['hex']} ({item['integer']})" for item in result["blocks"]
        )
        print(f"blocks:  {items}")
    return 0


def _run_modpow(args: argparse.Namespace) -> int:
    callback = _trace_printer(args.verbose) if args.verbose else None
    result = mod_pow(args.base, args.exponent, args.modulus, trace=callback)
    if args.json:
        print(json.dumps({"base": args.base, "exponent": args.exponent, "modulus": args.modulus, "result": result}, sort_keys=True))
    else:
        print(f"{args.base}^{args.exponent} mod {args.modulus} = {result}")
    return 0


def _run_rsa(args: argparse.Namespace) -> int:
    print(f"[educational] {EDUCATIONAL_WARNING}", file=sys.stderr)
    callback = _trace_printer(args.verbose) if args.verbose else None
    keys = RSAKeyPair.from_primes(args.p, args.q, public_exponent=args.e, trace=callback)
    encrypted = keys.public.encrypt_text(args.text, trace=callback)
    recovered = keys.private.decrypt_text(encrypted, trace=callback)
    result = {
        "educational_only": True,
        "public_key": {"n": keys.public.modulus, "e": keys.public.exponent},
        "private_exponent": keys.private.exponent,
        "plaintext": args.text,
        "encoded_byte_length": encrypted.byte_length,
        "block_size": encrypted.block_size,
        "ciphertext_blocks": list(encrypted.blocks),
        "recovered": recovered,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"public key:  (n={keys.public.modulus}, e={keys.public.exponent})")
        print(f"private d:   {keys.private.exponent}")
        print("ciphertext:  " + " ".join(map(str, encrypted.blocks)))
        print(f"recovered:   {recovered}")
    return 0


def _run_feistel(args: argparse.Namespace) -> int:
    print(f"[educational] {EDUCATIONAL_WARNING}", file=sys.stderr)
    callback = _trace_printer(args.verbose) if args.verbose else None
    cipher = ToyFeistelCipher(args.key, args.rounds)
    iv = None if args.mode == "ecb" else _hex_bytes(args.iv, length=8, label="IV")
    encrypted = cipher.encrypt(args.text.encode(), mode=args.mode, iv=iv, trace=callback)
    recovered = cipher.decrypt(encrypted, trace=callback).decode()
    result = {
        "educational_only": True,
        "mode": encrypted.mode,
        "rounds": args.rounds,
        "key": f"{args.key:016x}",
        "iv": encrypted.iv.hex() if encrypted.iv else None,
        "ciphertext_hex": encrypted.hex(),
        "plaintext": args.text,
        "recovered": recovered,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"mode/key:    {encrypted.mode.upper()} / {args.key:016x}")
        if encrypted.iv:
            print(f"IV:          {encrypted.iv.hex()}")
        print(f"ciphertext:  {encrypted.hex()}")
        print(f"recovered:   {recovered}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    runners = {
        "factor": _run_factor,
        "prime": _run_prime,
        "encode": _run_encode,
        "modpow": _run_modpow,
        "rsa-demo": _run_rsa,
        "feistel-demo": _run_feistel,
        **COURSE_RUNNERS,
    }
    try:
        return runners[args.command](args)
    except (FactorizationError, UnicodeError, ValueError) as error:
        print(f"crypto-lab: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
