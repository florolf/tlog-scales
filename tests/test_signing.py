import pytest
import dataclasses

import cryptography.hazmat.primitives.serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

from tlog_scales.signing import NoteSignature, PlainEd25519Signer, Vkey, VkeySet
from tlog_scales.tlog import Checkpoint


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
        msg = b'This is an example message.\n'

        vkey.get_verifier().verify_note(sig, msg)

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


class TestCheckpointSigning:
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


class TestVkeySetVerification:
    def test_valid(self) -> None:
        a = PlainEd25519Signer('a', b'a'*32)
        b = PlainEd25519Signer('b', b'b'*32)
        data = b'payload'
        sig_a = a.sign(data)
        sig_b = b.sign(data)

        valid = VkeySet(a.vkey, b.vkey).verify([sig_a, sig_b], data)
        assert valid == {(a.vkey, sig_a), (b.vkey, sig_b)}

    def test_skips_unknown_keys(self) -> None:
        a = PlainEd25519Signer('a', b'a'*32)
        b = PlainEd25519Signer('b', b'b'*32)
        data = b'payload'
        sig_a = a.sign(data)
        sig_b = b.sign(data)

        valid = VkeySet(a.vkey).verify([sig_a, sig_b], data)
        assert valid == {(a.vkey, sig_a)}

    def test_rejects_bad_data(self) -> None:
        signer = PlainEd25519Signer('a', b'a'*32)
        sig = signer.sign(b'payload')

        assert VkeySet(signer.vkey).verify([sig], b'foo') == set()

    def test_rejects_bad_sig(self) -> None:
        # Identity matches the known vkey, but the signature bytes are bogus
        signer = PlainEd25519Signer('a', b'a'*32)
        bad_sig = NoteSignature(signer.vkey.name, signer.vkey.key_id, b'\x00' * 64)

        assert VkeySet(signer.vkey).verify([bad_sig], b'hello') == set()
