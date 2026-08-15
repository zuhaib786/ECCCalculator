"""Command-line interface for :mod:`ecc_factor`."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from collections.abc import Sequence

from .events import FactorizationEvent
from .factorization import FactorizationError, factorize


def _positive_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not an integer: {value}") from error
    if parsed < 2:
        raise argparse.ArgumentTypeError("number must be at least 2")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ecc-factor",
        description="Factor an integer with trial division, Pollard rho, CFRAC, or ECM.",
    )
    parser.add_argument("number", type=_positive_int, help="integer to factor")
    parser.add_argument(
        "-m",
        "--method",
        choices=("auto", "trial", "rho", "ecm", "cfrac"),
        default="auto",
        help="factorization method (default: auto)",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="show progress; repeat for algorithm details",
    )
    output.add_argument(
        "-q", "--quiet", action="store_true", help="print only the prime factors"
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON result")
    parser.add_argument("--seed", type=int, help="seed randomized methods")
    parser.add_argument(
        "--trial-limit", type=int, default=100, metavar="N", help=argparse.SUPPRESS
    )
    parser.add_argument(
        "--ecm-bound", type=int, default=2_000, metavar="B1", help="ECM stage-one bound"
    )
    parser.add_argument(
        "--ecm-curves", type=int, default=50, metavar="N", help="ECM curve budget"
    )
    parser.add_argument(
        "--cfrac-bound",
        type=int,
        default=100,
        metavar="B",
        help="CFRAC factor-base bound",
    )
    parser.add_argument(
        "--cfrac-steps",
        type=int,
        default=10_000,
        metavar="N",
        help="CFRAC convergent budget",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.3.0")
    return parser


def _format_expression(number: int, factors: tuple[int, ...]) -> str:
    counts = Counter(factors)
    terms = [
        str(prime) if exponent == 1 else f"{prime}^{exponent}"
        for prime, exponent in counts.items()
    ]
    return f"{number} = {' * '.join(terms)}"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    def report(event: FactorizationEvent) -> None:
        if args.verbose >= event.level:
            print(f"[{event.code}] {event.message}", file=sys.stderr)

    try:
        factors = factorize(
            args.number,
            method=args.method,
            seed=args.seed,
            progress=report if args.verbose else None,
            trial_limit=args.trial_limit,
            ecm_bound=args.ecm_bound,
            ecm_curves=args.ecm_curves,
            cfrac_bound=args.cfrac_bound,
            cfrac_steps=args.cfrac_steps,
        )
    except (FactorizationError, ValueError) as error:
        print(f"ecc-factor: error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "number": args.number,
                    "factors": list(factors),
                    "method": args.method,
                },
                sort_keys=True,
            )
        )
    elif args.quiet:
        print(" ".join(map(str, factors)))
    else:
        print(_format_expression(args.number, factors))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
