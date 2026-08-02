import pytest
import dataclasses
import typing

import cryptography.hazmat.primitives.serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

from tlog_scales.signing import NoteSignature, PlainEd25519Signer, Vkey, VkeySet
from tlog_scales.tlog import Checkpoint
from tlog_scales.utils import sha256


class FakeCheckpoint:
    """
    Fake checkpoint for shoehorning the c2sp.org/signed-note test vector into
    our Checkpoint-only API. This works because the test vector uses plain
    Ed25519 keys which means the verifier implementation only relies on
    serialize_body() anyway.
    """

    def __init__(self, body: str):
        self.body = body

    def serialize_body(self) -> str:
        return self.body


def dummy_checkpoint(origin: str = 'example.com/log', size: int = 1) -> Checkpoint:
    return Checkpoint(origin, size, sha256(f'{origin} {size}'.encode()), [])


class TestC2SPSignedNote:
    """
    c2sp.org/signed-note test vectors
    """

    VKEY = 'example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k'

    def test_verifies_signature(self) -> None:
        vkey = Vkey.from_string(self.VKEY)
        sig = NoteSignature.from_line(
            '— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM='
        )
        cp  = typing.cast(Checkpoint, FakeCheckpoint('This is an example message.\n'))

        vkey.get_verifier().verify_note(sig, cp)

    def test_parsing(self) -> None:
        parsed = Vkey.from_string(self.VKEY)

        assert parsed.name == 'example.com/foo'
        assert parsed.pubkey == bytes.fromhex('e932791ae6e7a840a46164c904786426d5e7821dd8b29a00d61cae72afdd4da4')
        assert parsed.sig_type == 1
        assert parsed.key_id == 0x530d903a


    def test_key_id_derivation(self) -> None:
        parsed = Vkey.from_string(self.VKEY)
        derived = Vkey(parsed.name, None, parsed.sig_type, parsed.pubkey)
        assert derived.key_id == parsed.key_id


class TestVkey:
    def test_parsing_extra_plus(self) -> None:
        parsed = Vkey.from_string(
            'example.com/foo+00000000+++++++++++++++++++++++++++++++++++++++++++++'
        )

        assert parsed.name == 'example.com/foo'
        assert parsed.pubkey == bytes.fromhex('efbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbefbe')
        assert parsed.sig_type == 0xfb
        assert parsed.key_id == 0

    def test_serialize_roundtrip(self) -> None:
        original = PlainEd25519Signer('test', b'a'*32).vkey
        parsed = Vkey.from_string(original.serialize())

        assert parsed.name == original.name
        assert parsed.sig_type == original.sig_type
        assert parsed.pubkey == original.pubkey

    def test_key_id_out_of_range(self) -> None:
        with pytest.raises(ValueError):
            Vkey('name', -1, 1, b'\xaa' * 32)

        with pytest.raises(ValueError):
            Vkey('name', 0x100000000, 1, b'\xaa' * 32)

    def test_unknown_sig_type_has_no_verifier(self) -> None:
        with pytest.raises(NotImplementedError):
            Vkey('a', None, 0, b'\xaa' * 32).get_verifier()

class TestSigner:
    def test_pyca_private_key(self):
        pyca_pk = cryptography.hazmat.primitives.serialization.load_ssh_private_key("""
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA50+vDdfmj4VyEIRUNF+o3pLdFLFJP4shPHVh294PRjQAAAJCWzTQ+ls00
PgAAAAtzc2gtZWQyNTUxOQAAACA50+vDdfmj4VyEIRUNF+o3pLdFLFJP4shPHVh294PRjQ
AAAEDEBv5w5dRzhxOG4/EIj4tXndoiB8s9RIkVSnR6GjnDyTnT68N1+aPhXIQhFQ0X6jek
t0UsUk/iyE8dWHb3g9GNAAAADGZsYXJ5c2NoQGVvcwE=
-----END OPENSSH PRIVATE KEY-----
""".strip().encode(), None)

        assert isinstance(pyca_pk, Ed25519PrivateKey)
        signer = PlainEd25519Signer('foo', pyca_pk)
        assert signer.vkey.serialize() == 'foo+1573814f+ATnT68N1+aPhXIQhFQ0X6jekt0UsUk/iyE8dWHb3g9GN'


class TestCheckpointVerification:
    CHECKPOINT = Checkpoint.from_text("""
arche2025h1.staging.ct.transparency.dev
1432088532
U7WM79jrzyhGZ5/GUBTpM7NzwdyfFx61t3RovgcC4Ro=

— arche2025h1.staging.ct.transparency.dev zTM8sQAAAZ5W0WdjBAMARjBEAiBjW5IQf9pvsYLfQFX6hoGREPMHbdQ3urbllzalApkptQIgIpwtEroeW2BXaHAI4kJXFbon5Ch9MNL5zRNZ55lvGt0=
— arche2025h1.staging.ct.transparency.dev ui8GwCF1+kWqZrxGdhj4aX3gcw7XUlXQQabg/27lefwhUkzbC3NygNI75MdhL1bfTW9g8Ei59RA23oHP7Ry1k3ZFWwQ=
— transparency.dev/DEV:witness-little-garden 2AQqhwAAAABqEiEgzgFIqqhbUoDwjMWE6UP8nd8/KYTzwZ2rhIgcqoXHAwVkjZr4AscylP3v7sEodkRAErumC2q44vdgJY096st5BQ==
— witness1.smartit.nu/witness1 pIyCDwAAAABqEiEghIp82KWebrw7/oHQwlTAm3g2RKS4+eebl8eO0WH+/iEcxZ75W3u5hNI7TOQtmJbqmNWVuE0tgh0XwzdZsDsUAQ==
— remora.n621.de 2net5wAAAABqEiEgPlfF3V06o0Y+fHM+J5J9s27wgxxcOVSpZ/2g/KSiXCg9DEZI+aVCIobWX9sXTynk5XeU/zZ0WBxtqB0DrAWfBw==
— witness.stagemole.eu Z/euoAAAAABqEiEgw0i+7g2ENfDAWHmtRzCfKTHSDwYDJA2NmKeGi9Y8FtEyOUvVr+AJmIY/2TUFucgKi7lI7cUiOvKFYe/TmN9DAg==
""".strip())

    VKEYS = [
        Vkey.from_string('arche2025h1.staging.ct.transparency.dev+ba2f06c0+AU0vHmlGCS/PdN8b2OaGmKprLI8HKM+dJ472xgFYh15f'),
        Vkey.from_string('remora.n621.de+da77ade7+BOvN63jn/bLvkieywe8R6UYAtVtNbZpXh34x7onlmtw2')
    ]

    def test_real_checkpoint(self) -> None:
        for vkey in self.VKEYS:
            self.CHECKPOINT.verify(vkey)

    def test_real_checkpoint_clobbered(self) -> None:
        cp2 = dataclasses.replace(self.CHECKPOINT, size=42)

        for vkey in self.VKEYS:
            with pytest.raises(InvalidSignature):
                cp2.verify(vkey)

    def test_missing_key_fails(self) -> None:
        vkey = Vkey.from_string('example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k')
        with pytest.raises(match='no signature matched'):
            self.CHECKPOINT.verify(vkey)

    def test_make_signed_verifies(self) -> None:
        signer = PlainEd25519Signer('log', b'a'*32)
        cp = Checkpoint.make_signed('example.com/log', 1, b'\x00' * 32, [signer])
        cp.verify(signer.vkey)


class TestMLDSA44Verification:
    CHECKPOINT = Checkpoint.from_text("""
coachandhorses2026h1.staging.certificate.transparency.goog
185550722
YXAM0VmnrfvLaBCOOYSJhCaE5F10oGBOo+hkbDa1kng=

— coachandhorses2026h1.staging.certificate.transparency.goog MpXgsHy8ZwxXnO+WjtVrPxAzL49Rs1gWTkNVNeEa//5peAzaocRCB3qt3EaibjzY5GILLtGgBP7dBhgcSHy+JQh0OAc=
— witness.navigli.sunlight.geomys.org o+AP4gAAAABqb7DzNrGFRJnQ9vrJ8xpnwZytnr/ZYczDIsvwvouiSjwOjn7a72ccxBk+lKnZ7dKqkYKER1s/KxLTaVwQD7lJZTC/CQ==
— witness.navigli.sunlight.geomys.org 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
""".strip())

    VKEY = Vkey.from_string('witness.navigli.sunlight.geomys.org+6bc44249+BvKbJzZZb2L5kdgqACS68/hxJoQQ88Zhp7esVL81HYRPQAurY9cfky201kuNm1oSO71BiNPWC8oNHunBo/PnRD/eWIuu/ZPIsiG0Cq9xg8dJsoKuQGXJ2Hu1QLBoyFWUFWAtmURCRi5bXFYJjVy4fFFh5ClS477HTy7av3C6VvnOdYTH1jISdXyIblBTWkQEq24gMc2JZKiS5YleWbXjlVuDKaU3yQjDhyWTd8AZuCvrcC9rE8wOZ7etpkAEf2pPINQ4LnMEHCWTuEE5NZwGWwqcekXvNQvv1jjfWQkhSzXbFvbLmifpWxRFrHn9OSEPGfaCksRUvKoTZzOrIPuFAhAraDIXX0DLwc7xY9hcg2lGpCaDoOXoyAS6m4wGiqerd0kLjFitkgJ7A/tpIcO+m255eyWnZwrevWaFgx+xwN7OjdJTlGMK9Qgd7QJW1Qilmt/h1SqZGpithCfje+/MiUea2eyTKbPBCf5c206/5Axu789uL1v22XZRO5tfDPLpU5lTPYdD0dt9M4I02G/2mHsZ43dbcsSYe0i+oM6GgIV0CoTx833GJMCjOOZbo3Qmlxwf3QFhkwGtc/db16iDfCW0U2NINxuSyDGahEIudOyNldfh+oe3tLyICiNGF3kGRQ1MRLD+e6AakJsjat9wMgjORHWx1rE7r14wCZtxFkSjOjSMpN8DiBXtGySSnWv2jKWnYnLPYhdqTJMEAZLLtd5Elaq+DukrJfmR5Jx348lx0E8AjALfg1oYQSCBKYlUN7h4kJhZhYGu6ahVPp1OBlA+DuBfoMtE6IiTfm11LseSOyNOtNTFe5V508Dw/APhoKuxy0mTAmEDmPnXTBvHhX1PVhl1qHTmfNhpukzxBRPKzsVN7y/FuJuqrX208k7SihRJGtDsXkQK/cFzTmSGvyHEKK+IHoKFpRK0dxEV6muqPJEEzehwZrJ7Rz0ZfkjuKVCiP98md+yD+r7GD2BjIb3IEzhrsbf5Ak7f5NImP4UoL6vy48ZfwmEo6tvn6StSVd912GYobRKHzboTBhUIn8c93VIX7PAQ64exm4l9wUBr3KMzHuykTW9m7C1xw1+Oqf3PGWN9rLHXNMPaR08xnImkTd+W74ls1sHH1CzJiNJB5QZg44zCajgL131L9G62AuTth/zJeGovddDU1m7N3i+e2Qz/omDKILlfUtcwPyyWeSvW/XX0ECFp/o9cDh/l6S5mcaT2Mtiiyn+owXl4Mx85Yppi2ZvVpZudLyhM0AGeoDdRRlfdeaJsvfC7pzBKzbj/1CKs7Ts962kvpCoDyZ5rMBK5PhFLvNXhl9ntKSTIAqUoM3vPgouzrA57Y9G5cWEJ741G4siABCFedWcDKT5zXKO682fncspp2MLjGCqNEWbSRRJ957q/W5mUyI1sDiXsKaaxGq0Xg86qu1AaEd7EBgOLj3i762ANsbZqtButkOdGD+MVeELpgNiOttWPW6Xq0ERM5NcJgezQJghy+y7IKf6zqrud4Ql6pklvjTuzCeLVsfpWQsqfgF4W0ZADldLfPCJIDBby1sxjh32i6hIp2R7QC6Mp87k9PAa5fiFDOqJXqDtGLxKPKu6UPdvbJHfHx4M37F6mfQnst4Bkjgf0kLGkW9isZ7bnids+QclIgfKFjZ5mD+ekGKo835+G44y7zAauKZzj8nBiNMSYwdAEMn6TYHciHn1VyetNEtzSMHInsV30TOnahKfkNgvAuNCuxrIyNvFHCw9t3vRr/J0=')

    def test_verify(self) -> None:
        self.CHECKPOINT.verify(self.VKEY)

    def test_verify_clobbered(self) -> None:
        cp2 = dataclasses.replace(self.CHECKPOINT, size=42)

        with pytest.raises(InvalidSignature):
            cp2.verify(self.VKEY)

class TestVkeySetVerification:
    def test_valid(self) -> None:
        a = PlainEd25519Signer('a', b'a'*32)
        b = PlainEd25519Signer('b', b'b'*32)
        cp = dummy_checkpoint()
        sig_a = a.sign(cp)
        sig_b = b.sign(cp)

        valid = VkeySet(a.vkey, b.vkey).verify([sig_a, sig_b], cp)
        assert valid == {(a.vkey, sig_a), (b.vkey, sig_b)}

    def test_skips_unknown_keys(self) -> None:
        a = PlainEd25519Signer('a', b'a'*32)
        b = PlainEd25519Signer('b', b'b'*32)
        cp = dummy_checkpoint()
        sig_a = a.sign(cp)
        sig_b = b.sign(cp)

        valid = VkeySet(a.vkey).verify([sig_a, sig_b], cp)
        assert valid == {(a.vkey, sig_a)}

    def test_rejects_bad_data(self) -> None:
        signer = PlainEd25519Signer('a', b'a'*32)
        sig = signer.sign(dummy_checkpoint(size=1))

        assert VkeySet(signer.vkey).verify([sig], dummy_checkpoint(size=2)) == set()

    def test_rejects_bad_sig(self) -> None:
        # Identity matches the known vkey, but the signature bytes are bogus
        signer = PlainEd25519Signer('a', b'a'*32)
        bad_sig = NoteSignature(signer.vkey.name, signer.vkey.key_id, b'\x00' * 64)

        assert VkeySet(signer.vkey).verify([bad_sig], dummy_checkpoint()) == set()
