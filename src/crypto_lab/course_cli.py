"""Extended first-course commands registered by :mod:`crypto_lab.cli`."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Callable

from .advanced_topics import (
    lwe_decrypt_bit,
    lwe_encrypt_bit,
    lwe_keygen,
    mpc_secure_sum,
    schnorr_prove,
    schnorr_public_key,
    schnorr_verify,
    simulate_bb84,
)
from .attacks import recover_cbc_last_block, recover_with_prefix_oracle
from .authentication import hmac_sha256, verify_hmac
from .classical import (
    affine_decrypt,
    affine_encrypt,
    caesar_decrypt,
    caesar_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)
from .discrete_log import (
    baby_step_giant_step,
    pohlig_hellman,
    pollard_rho_discrete_log,
)
from .feistel import ToyFeistelCipher
from .hashing import length_extension_attack, toy_hash, verify_length_extension
from .key_exchange import diffie_hellman
from .lessons import get_lesson, list_lessons
from .protocols import simplified_tls_handshake
from .secret_sharing import shamir_recover, shamir_split
from .security_games import (
    DeterministicXorScheme,
    RandomNonceXorScheme,
    run_ind_cpa_equality_game,
)
from .signatures import (
    DSAKeyPair,
    ECDSAKeyPair,
    dsa_sign,
    dsa_verify,
    ecdsa_sign,
    ecdsa_verify,
    lamport_keygen,
    lamport_sign,
    lamport_verify,
    rsa_sign,
    rsa_verify,
)
from .symmetric import AES128
from .rsa import RSAKeyPair


def _integer(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not an integer: {value}") from error


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-v", "--verbose", action="count", default=0)
    parser.add_argument("--json", action="store_true")


def register_course_commands(commands: argparse._SubParsersAction) -> None:
    lessons = commands.add_parser("lessons", help="list or inspect the course lessons")
    lessons.add_argument("slug", nargs="?")
    lessons.add_argument("--unit")
    lessons.add_argument("--json", action="store_true")

    classical = commands.add_parser("classical", help="run a classical cipher lesson")
    classical.add_argument("cipher", choices=("caesar", "affine", "vigenere"))
    classical.add_argument("text")
    classical.add_argument("--decrypt", action="store_true")
    classical.add_argument("--shift", type=int, default=3)
    classical.add_argument("--a", type=int, default=5)
    classical.add_argument("--b", type=int, default=8)
    classical.add_argument("--key", default="LEMON")
    _common(classical)

    aes = commands.add_parser("aes-demo", help="trace one standards-compatible AES-128 block")
    aes.add_argument("block", help="16-byte block in hexadecimal")
    aes.add_argument("--key", default="000102030405060708090a0b0c0d0e0f")
    aes.add_argument("--decrypt", action="store_true")
    _common(aes)

    game = commands.add_parser("security-game", help="run the IND-CPA equality experiment")
    game.add_argument("--scheme", choices=("deterministic", "randomized"), default="deterministic")
    game.add_argument("--trials", type=int, default=1_000)
    game.add_argument("--seed", type=int, default=7)
    _common(game)

    dlog = commands.add_parser("dlog", help="solve a discrete logarithm")
    dlog.add_argument("base", type=_integer)
    dlog.add_argument("target", type=_integer)
    dlog.add_argument("modulus", type=_integer)
    dlog.add_argument("--algorithm", choices=("bsgs", "pohlig-hellman", "rho"), default="bsgs")
    dlog.add_argument("--seed", type=int, default=4)
    _common(dlog)

    dh = commands.add_parser("dh-demo", help="run finite-field Diffie-Hellman")
    dh.add_argument("--prime", type=int, default=23)
    dh.add_argument("--generator", type=int, default=5)
    dh.add_argument("--alice", type=int, default=6)
    dh.add_argument("--bob", type=int, default=15)
    _common(dh)

    shamir = commands.add_parser("shamir-demo", help="split and recover a Shamir secret")
    shamir.add_argument("secret", type=int)
    shamir.add_argument("--threshold", type=int, default=3)
    shamir.add_argument("--shares", type=int, default=5)
    shamir.add_argument("--prime", type=int, default=257)
    shamir.add_argument("--seed", type=int, default=9)
    _common(shamir)

    hash_demo = commands.add_parser("hash-demo", help="show a Merkle-Damgard length extension")
    hash_demo.add_argument("message")
    hash_demo.add_argument("--extension", default="&admin=true")
    _common(hash_demo)

    auth = commands.add_parser("auth-demo", help="compute and verify HMAC-SHA256")
    auth.add_argument("message")
    auth.add_argument("--key", default="classroom key")
    _common(auth)

    signature = commands.add_parser("signature-demo", help="sign and verify with a teaching scheme")
    signature.add_argument("message")
    signature.add_argument("--scheme", choices=("rsa", "lamport", "dsa", "ecdsa"), default="rsa")
    signature.add_argument("--seed", type=int, default=17)
    _common(signature)

    attack = commands.add_parser("attack-demo", help="run a timing or padding-oracle attack")
    attack.add_argument("attack", choices=("timing", "padding-oracle"))
    attack.add_argument("--secret", default="MAC!")
    _common(attack)

    advanced = commands.add_parser("advanced-demo", help="run ZK, LWE, MPC, or BB84")
    advanced.add_argument("topic", choices=("zk", "lwe", "mpc", "bb84"))
    advanced.add_argument("--seed", type=int, default=7)
    advanced.add_argument("--eve", type=float, default=0.0)
    _common(advanced)

    tls = commands.add_parser("tls-demo", help="show a simplified DH/TLS transcript")
    _common(tls)


def _callback(args: argparse.Namespace):
    def report(event) -> None:
        if args.verbose >= event.level:
            print(f"[{event.code}] {event.message}", file=sys.stderr)

    return report if args.verbose else None


def _print(payload: dict, args: argparse.Namespace, lines: list[str]) -> int:
    if args.json:
        print(json.dumps(payload, sort_keys=True, default=str))
    else:
        print("\n".join(lines))
    return 0


def _run_lessons(args: argparse.Namespace) -> int:
    selected = [get_lesson(args.slug)] if args.slug else list(list_lessons(unit=args.unit))
    payload = [lesson.as_dict() for lesson in selected]
    if args.json:
        print(json.dumps(payload[0] if args.slug else payload, sort_keys=True))
    elif args.slug:
        lesson = selected[0]
        print(f"{lesson.title}\n{lesson.summary}\nconcepts: {', '.join(lesson.concepts)}")
    else:
        for index, lesson in enumerate(selected, start=1):
            print(f"{index:02}. {lesson.slug:24} {lesson.title}")
    return 0


def _run_classical(args: argparse.Namespace) -> int:
    trace = _callback(args)
    if args.cipher == "caesar":
        function = caesar_decrypt if args.decrypt else caesar_encrypt
        result = function(args.text, args.shift, trace=trace)
    elif args.cipher == "affine":
        function = affine_decrypt if args.decrypt else affine_encrypt
        result = function(args.text, args.a, args.b, trace=trace)
    else:
        function = vigenere_decrypt if args.decrypt else vigenere_encrypt
        result = function(args.text, args.key, trace=trace)
    return _print({"cipher": args.cipher, "result": result}, args, [result])


def _run_aes(args: argparse.Namespace) -> int:
    block, key = bytes.fromhex(args.block), bytes.fromhex(args.key)
    cipher = AES128(key)
    result = (
        cipher.decrypt_block(block, trace=_callback(args))
        if args.decrypt
        else cipher.encrypt_block(block, trace=_callback(args))
    )
    return _print({"result": result.hex()}, args, [result.hex()])


def _run_game(args: argparse.Namespace) -> int:
    scheme = (
        DeterministicXorScheme(b"course key")
        if args.scheme == "deterministic"
        else RandomNonceXorScheme(b"course key")
    )
    result = run_ind_cpa_equality_game(
        scheme,
        b"message zero",
        b"message one!",
        trials=args.trials,
        seed=args.seed,
        trace=_callback(args),
    )
    payload = {
        "scheme": args.scheme,
        "wins": result.wins,
        "trials": result.trials,
        "success_rate": result.success_rate,
        "advantage": result.distinguishing_advantage,
    }
    return _print(payload, args, [f"success: {result.success_rate:.3f}", f"advantage: {result.distinguishing_advantage:.3f}"])


def _run_dlog(args: argparse.Namespace) -> int:
    functions: dict[str, Callable] = {
        "bsgs": baby_step_giant_step,
        "pohlig-hellman": pohlig_hellman,
        "rho": pollard_rho_discrete_log,
    }
    kwargs = {"trace": _callback(args)}
    if args.algorithm == "rho":
        kwargs["seed"] = args.seed
    result = functions[args.algorithm](args.base, args.target, args.modulus, **kwargs)
    return _print({"algorithm": args.algorithm, "discrete_log": result}, args, [f"discrete log: {result}"])


def _run_dh(args: argparse.Namespace) -> int:
    shared = diffie_hellman(
        args.prime, args.generator, args.alice, args.bob, trace=_callback(args)
    )
    return _print({"shared_secret": shared}, args, [f"shared secret: {shared}"])


def _run_shamir(args: argparse.Namespace) -> int:
    shares = shamir_split(
        args.secret,
        args.threshold,
        args.shares,
        args.prime,
        seed=args.seed,
        trace=_callback(args),
    )
    recovered = shamir_recover(shares[: args.threshold], args.prime, trace=_callback(args))
    payload = {
        "shares": [(share.index, share.value) for share in shares],
        "recovered": recovered,
    }
    return _print(payload, args, [f"shares: {payload['shares']}", f"recovered: {recovered}"])


def _run_hash(args: argparse.Namespace) -> int:
    message, extension = args.message.encode(), args.extension.encode()
    forged = length_extension_attack(
        toy_hash(message), len(message), extension, trace=_callback(args)
    )
    valid = verify_length_extension(message, forged)
    payload = {"digest": forged.digest.hex(), "forged_suffix": forged.forged_suffix.hex(), "verified": valid}
    return _print(payload, args, [f"forged digest: {forged.digest.hex()}", f"verified: {valid}"])


def _run_auth(args: argparse.Namespace) -> int:
    tag = hmac_sha256(args.key.encode(), args.message.encode(), trace=_callback(args))
    valid = verify_hmac(args.key.encode(), args.message.encode(), tag)
    return _print({"tag": tag.hex(), "verified": valid}, args, [f"tag: {tag.hex()}", f"verified: {valid}"])


def _run_signature(args: argparse.Namespace) -> int:
    message = args.message.encode()
    if args.scheme == "rsa":
        keys = RSAKeyPair.from_primes(61, 53, public_exponent=17)
        signature = rsa_sign(message, keys, trace=_callback(args))
        valid, shown = rsa_verify(message, signature, keys), signature
    elif args.scheme == "lamport":
        keys = lamport_keygen(seed=args.seed)
        signature = lamport_sign(keys.private, message, trace=_callback(args))
        valid, shown = lamport_verify(keys.public, message, signature), "256 revealed values"
    elif args.scheme == "dsa":
        keys = DSAKeyPair.generate(private_key=7)
        for offset in range(keys.parameters.q - 1):
            nonce = (args.seed + offset) % (keys.parameters.q - 1) + 1
            try:
                signature = dsa_sign(message, keys, nonce=nonce, trace=_callback(args))
                break
            except ValueError as error:
                if "selected nonce produced" not in str(error):
                    raise
        else:  # pragma: no cover - valid parameters always have a usable nonce
            raise ValueError("could not find a valid DSA teaching nonce")
        valid, shown = dsa_verify(message, signature, keys), (signature.r, signature.s)
    else:
        keys = ECDSAKeyPair.generate(private_key=5)
        for offset in range(keys.parameters.order - 1):
            nonce = (args.seed + offset) % (keys.parameters.order - 1) + 1
            try:
                signature = ecdsa_sign(message, keys, nonce=nonce, trace=_callback(args))
                break
            except ValueError as error:
                if "selected nonce produced" not in str(error):
                    raise
        else:  # pragma: no cover - valid parameters always have a usable nonce
            raise ValueError("could not find a valid ECDSA teaching nonce")
        valid, shown = ecdsa_verify(message, signature, keys), (signature.r, signature.s)
    return _print({"scheme": args.scheme, "signature": shown, "verified": valid}, args, [f"signature: {shown}", f"verified: {valid}"])


def _run_attack(args: argparse.Namespace) -> int:
    if args.attack == "timing":
        recovered = recover_with_prefix_oracle(args.secret.encode(), trace=_callback(args))
        payload = {"recovered": recovered.decode()}
        lines = [f"recovered: {recovered.decode()}"]
    else:
        cipher = ToyFeistelCipher(0x1334_5779_9BBC_DFF1)
        message = cipher.encrypt(b"padding oracle lesson", mode="cbc", iv=bytes(8))
        recovered, queries = recover_cbc_last_block(cipher, message, trace=_callback(args))
        payload = {"padded_block": recovered.hex(), "queries": queries}
        lines = [f"padded block: {recovered!r}", f"oracle queries: {queries}"]
    return _print(payload, args, lines)


def _run_advanced(args: argparse.Namespace) -> int:
    trace = _callback(args)
    if args.topic == "zk":
        public = schnorr_public_key(7, prime=23, generator=2)
        proof = schnorr_prove(7, nonce=4, challenge=3, prime=23, subgroup_order=11, generator=2, trace=trace)
        payload = {"commitment": proof.commitment, "challenge": proof.challenge, "response": proof.response, "verified": schnorr_verify(public, proof, prime=23, generator=2)}
    elif args.topic == "lwe":
        keys = lwe_keygen(seed=args.seed, trace=trace)
        ciphertext = lwe_encrypt_bit(1, keys.public, seed=args.seed + 1, trace=trace)
        payload = {"decrypted_bit": lwe_decrypt_bit(ciphertext, keys), "ciphertext": [ciphertext.vector, ciphertext.value]}
    elif args.topic == "mpc":
        payload = {"secure_sum": mpc_secure_sum((10, 20, 30), 101, seed=args.seed, trace=trace)}
    else:
        result = simulate_bb84(1_000, seed=args.seed, intercept_probability=args.eve, trace=trace)
        payload = {"sifted_bits": len(result.sifted_alice), "error_rate": result.error_rate, "intercepted": result.intercepted}
    return _print(payload, args, [f"{key}: {value}" for key, value in payload.items()])


def _run_tls(args: argparse.Namespace) -> int:
    transcript = simplified_tls_handshake(
        prime=23,
        generator=5,
        client_private=6,
        server_private=15,
        client_nonce=b"client nonce",
        server_nonce=b"server nonce",
        trace=_callback(args),
    )
    payload = {"client_share": transcript.client_public, "server_share": transcript.server_public, "shared_secret": transcript.shared_secret, "transcript_hash": transcript.transcript_hash.hex()}
    return _print(payload, args, [f"shared secret: {transcript.shared_secret}", f"transcript hash: {transcript.transcript_hash.hex()}"])


COURSE_RUNNERS = {
    "lessons": _run_lessons,
    "classical": _run_classical,
    "aes-demo": _run_aes,
    "security-game": _run_game,
    "dlog": _run_dlog,
    "dh-demo": _run_dh,
    "shamir-demo": _run_shamir,
    "hash-demo": _run_hash,
    "auth-demo": _run_auth,
    "signature-demo": _run_signature,
    "attack-demo": _run_attack,
    "advanced-demo": _run_advanced,
    "tls-demo": _run_tls,
}


__all__ = ["COURSE_RUNNERS", "register_course_commands"]
