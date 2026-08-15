from __future__ import annotations

import unittest

from crypto_lab.attacks import (
    cbc_bitflip,
    recover_cbc_last_block,
    recover_with_prefix_oracle,
)
from crypto_lab.feistel import FeistelMessage, ToyFeistelCipher


class AttackLabsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cipher = ToyFeistelCipher(0x1334_5779_9BBC_DFF1)

    def test_prefix_timing_oracle_recovers_secret(self) -> None:
        events = []
        self.assertEqual(
            recover_with_prefix_oracle(b"MAC!", trace=events.append), b"MAC!"
        )
        self.assertEqual(len(events), 4)

    def test_cbc_bitflip_changes_chosen_plaintext_byte(self) -> None:
        plaintext = b"header!!admin=0;"
        packet = self.cipher.encrypt(plaintext, mode="cbc", iv=bytes(8))
        blocks = [packet.ciphertext[i : i + 8] for i in range(0, len(packet.ciphertext), 8)]
        modified_first = cbc_bitflip(
            blocks[0], offset=6, known_plaintext_byte=ord("0"), desired_plaintext_byte=ord("1")
        )
        modified = FeistelMessage(
            modified_first + b"".join(blocks[1:]), "cbc", packet.iv
        )
        recovered = self.cipher.decrypt(modified)
        self.assertEqual(recovered[8 + 6], ord("1"))

    def test_padding_oracle_recovers_final_padded_block(self) -> None:
        packet = self.cipher.encrypt(
            b"padding oracle lesson", mode="cbc", iv=bytes.fromhex("0001020304050607")
        )
        recovered, queries = recover_cbc_last_block(self.cipher, packet)
        self.assertEqual(recovered, b"esson\x03\x03\x03")
        self.assertGreater(queries, 8)


if __name__ == "__main__":
    unittest.main()
