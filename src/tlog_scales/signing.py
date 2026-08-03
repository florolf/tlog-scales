from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA44PublicKey,
)

from .utils import b64dec, b64enc, sha256

if TYPE_CHECKING:
    from .tlog import Checkpoint

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class NoteSignature:
    name: str
    key_id: int
    payload: bytes

    def __str__(self) -> str:
        return f"NoteSignature(name={self.name}, key_id={self.key_id:08x}, payload={self.payload.hex()})"

    def serialize(self) -> str:
        return f'\u2014 {self.name} {b64enc(self.key_id.to_bytes(4) + self.payload)}'

    @classmethod
    def from_line(cls, line: str) -> Self:
        if line[0] != '\u2014':
            raise ValueError('em-dash missing')

        _, name, blob = line.split()
        payload = b64dec(blob)
        key_id = int.from_bytes(payload[:4])

        return cls(name, key_id, payload[4:])

    @classmethod
    def from_vkey_signature(cls, vkey: Vkey, signature: bytes) -> Self:
        return cls(vkey.name, vkey.key_id, signature)


def _mldsa44_signature_payload(signer: str, timestamp: int, cp: Checkpoint) -> bytes:
    data = bytearray()

    def append_u8_vector(payload: bytes) -> None:
        nonlocal data
        data += len(payload).to_bytes(1)
        data += payload

    data += b'subtree/v1\n\0'
    append_u8_vector(signer.encode())
    data += timestamp.to_bytes(8)
    append_u8_vector(cp.origin.encode())
    data += (0).to_bytes(8) # start must be 0 for checkpoints
    data += cp.size.to_bytes(8)
    data += cp.root_hash

    return bytes(data)


class CheckpointSigner(Protocol):
    vkey: Vkey

    def sign(self, cp: Checkpoint) -> NoteSignature:
        ...


class DummySigner:
    def __init__(self, name: str = 'dummy', key_id: int | None = None):
        self.vkey = Vkey(name, key_id, 0, b'')

    def sign(self, cp: Checkpoint) -> NoteSignature:
        return NoteSignature.from_vkey_signature(self.vkey, sha256(cp.serialize_body().encode()))


class PlainEd25519Signer:
    def __init__(self, name: str, key: Ed25519PrivateKey | bytes):
        if isinstance(key, bytes):
            self.key = Ed25519PrivateKey.from_private_bytes(key)
        else:
            self.key = key

        self.vkey = Vkey(name, None, 1, self.key.public_key().public_bytes_raw())

    def sign(self, cp: Checkpoint) -> NoteSignature:
        sig = self.key.sign(cp.serialize_body().encode())
        return NoteSignature.from_vkey_signature(self.vkey, sig)


class MLDSA44CosignatureSigner:
    def __init__(self, name: str, key: MLDSA44PrivateKey | bytes):
        if isinstance(key, bytes):
            self.key = MLDSA44PrivateKey.from_seed_bytes(key)
        else:
            self.key = key

        self.vkey = Vkey(name, None, 6, self.key.public_key().public_bytes_raw())

    def sign(self, cp: Checkpoint) -> NoteSignature:
        now = int(time.time())
        sig_payload = _mldsa44_signature_payload(self.vkey.name, now, cp)
        data = now.to_bytes(8) + self.key.sign(sig_payload)
        return NoteSignature.from_vkey_signature(self.vkey, data)


class VkeyVerifier(ABC):
    vkey: Vkey

    def __init__(self, vkey: Vkey):
        self.vkey = vkey

    @abstractmethod
    def verify(self, signature: bytes, cp: Checkpoint) -> None:
        raise NotImplementedError

    def verify_note(self, note: NoteSignature, cp: Checkpoint) -> None:
        if not self.vkey.match(note):
            raise RuntimeError(f"verifier {self} doesn't match note signature {note}")

        self.verify(note.payload, cp)


class PlainEd25519Verifier(VkeyVerifier):
    def __init__(self, vkey: Vkey):
        assert vkey.sig_type == 1

        super().__init__(vkey)
        self.key = Ed25519PublicKey.from_public_bytes(vkey.pubkey)

    def __str__(self) -> str:
        return f'PlainEd25519Verifier({self.vkey})'

    def verify(self, signature: bytes, cp: Checkpoint) -> None:
        data = cp.serialize_body().encode()
        self.key.verify(signature, data)


class Ed25519CosignatureVerifier(VkeyVerifier):
    def __init__(self, vkey: Vkey):
        assert vkey.sig_type == 4

        super().__init__(vkey)
        self.key = Ed25519PublicKey.from_public_bytes(vkey.pubkey)

    def __str__(self) -> str:
        return f'Ed25519CosignatureVerifier({self.vkey})'

    @staticmethod
    def get_timestamp(signature: bytes) -> int:
        return int.from_bytes(signature[0:8])

    def verify(self, signature: bytes, cp: Checkpoint):
        timestamp = self.get_timestamp(signature)
        message = f'cosignature/v1\ntime {timestamp}\n'.encode()
        message += cp.serialize_body().encode()

        self.key.verify(signature[8:], message)


class MLDSA44CosignatureVerifier(VkeyVerifier):
    def __init__(self, vkey: Vkey):
        assert vkey.sig_type == 6

        super().__init__(vkey)
        self.cosigner_name  = vkey.name
        self.key = MLDSA44PublicKey.from_public_bytes(vkey.pubkey)

    def __str__(self) -> str:
        return f'MLDSA44CosignatureVerifier({self.vkey})'

    @staticmethod
    def get_timestamp(signature: bytes) -> int:
        return int.from_bytes(signature[0:8])

    def verify(self, signature: bytes, cp: Checkpoint):
        data = _mldsa44_signature_payload(
            self.cosigner_name,
            self.get_timestamp(signature),
            cp
        )
        self.key.verify(signature[8:], data)


class Vkey:
    def __init__(self, name: str, key_id: int | None, sig_type: int, pubkey: bytes):
        self.name = name

        if key_id is None:
            h = sha256(name.encode() + b'\x0a' + sig_type.to_bytes() + pubkey)
            key_id = int.from_bytes(h[:4])
        elif not (0 <= key_id <= 0xffffffff):
            raise ValueError(f'key_id {key_id:x} out of range')

        self.key_id = key_id

        self.sig_type = sig_type
        self.pubkey = pubkey

    def __str__(self) -> str:
        return f'Vkey(name={self.name}, key_id={self.key_id:08x}, sig_type={self.sig_type}, pubkey={self.pubkey.hex()})'

    def serialize(self):
        return f'{self.name}+{self.key_id:08x}+{b64enc(self.sig_type.to_bytes() + self.pubkey)}'

    @classmethod
    def from_string(cls, vkey: str) -> Self:
        name, key_id_str, b64 = vkey.split('+', maxsplit=2)

        key_id = int.from_bytes(bytes.fromhex(key_id_str))
        payload = b64dec(b64)

        return cls(name, key_id, payload[0], payload[1:])

    def match(self, signature: NoteSignature) -> bool:
        return self.key_id == signature.key_id and self.name == signature.name

    def get_verifier(self) -> VkeyVerifier:
        match self.sig_type:
            case 1:
                return PlainEd25519Verifier(self)
            case 4:
                return Ed25519CosignatureVerifier(self)
            case 6:
                return MLDSA44CosignatureVerifier(self)
            case _:
                raise NotImplementedError(f'unsupported signature type {self.sig_type} for verification')


class VkeySet:
    def __init__(self, *args: Vkey):
        self.keys: dict[tuple[str, int], Vkey] = {}

        for arg in args:
            self.add(arg)

    def add(self, vkey: Vkey) -> None:
        self.keys[(vkey.name, vkey.key_id)] = vkey

    def verify(self, sigs: Iterable[NoteSignature], cp: Checkpoint) -> set[tuple[Vkey, NoteSignature]]:
        valid = set()

        for sig in sigs:
            vkey = self.keys.get((sig.name, sig.key_id))
            if vkey is None:
                continue

            verifier = vkey.get_verifier()
            try:
                verifier.verify_note(sig, cp)
                valid.add((vkey, sig))
            except Exception as e:
                logger.warning(f'verifying {sig} on {cp} and vkey {vkey} failed', exc_info=e)

        return valid
