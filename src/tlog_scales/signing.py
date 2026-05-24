from dataclasses import dataclass
from typing import Protocol, Self, Iterable, Optional
from abc import ABC, abstractmethod
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey

from .utils import b64enc, b64dec, sha256

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
    def from_vkey_signature(cls, vkey: 'Vkey', signature: bytes) -> Self:
        return cls(vkey.name, vkey.key_id, signature)


class NoteSigner(Protocol):
    vkey: 'Vkey'

    def sign(self, data: bytes) -> NoteSignature:
        ...


class DummySigner:
    def __init__(self, name: str = 'dummy', key_id: Optional[int] = None):
        self.vkey = Vkey(name, key_id, 0, b'')

    def sign(self, data: bytes) -> NoteSignature:
        return NoteSignature.from_vkey_signature(self.vkey, sha256(data))


class PlainEd25519Signer:
    def __init__(self, name: str, key: Ed25519PrivateKey | bytes):
        if isinstance(key, bytes):
            self.key = Ed25519PrivateKey.from_private_bytes(key)
        else:
            self.key = key

        self.vkey = Vkey(name, None, 1, self.key.public_key().public_bytes_raw())

    def sign(self, data: bytes) -> NoteSignature:
        sig = self.key.sign(data)
        return NoteSignature.from_vkey_signature(self.vkey, sig)


class VkeyVerifier(ABC):
    vkey: 'Vkey'

    def __init__(self, vkey: 'Vkey'):
        self.vkey = vkey

    @abstractmethod
    def verify(self, signature: bytes, data: bytes) -> None:
        raise NotImplementedError

    def verify_note(self, note: NoteSignature, data: bytes) -> None:
        if not self.vkey.match(note):
            raise RuntimeError(f"verifier {self} doesn't match note signature {note}")

        self.verify(note.payload, data)


class PlainEd25519Verifier(VkeyVerifier):
    def __init__(self, vkey: 'Vkey'):
        assert vkey.sig_type == 1

        super().__init__(vkey)
        self.key = Ed25519PublicKey.from_public_bytes(vkey.pubkey)

    def __str__(self) -> str:
        return f'PlainEd25519Verifier({self.vkey})'

    def verify(self, signature: bytes, data: bytes) -> None:
        self.key.verify(signature, data)


class Ed25519CosignatureVerifier(VkeyVerifier):
    def __init__(self, vkey: 'Vkey'):
        assert vkey.sig_type == 4

        super().__init__(vkey)
        self.key = Ed25519PublicKey.from_public_bytes(vkey.pubkey)

    def __str__(self) -> str:
        return f'Ed25519CosignatureVerifier({self.vkey})'

    def get_timestamp(self, signature: bytes) -> int:
        return int.from_bytes(signature[0:8])

    def verify(self, signature: bytes, data: bytes):
        timestamp = self.get_timestamp(signature)
        message = f'cosignature/v1\ntime {timestamp}\n'.encode()
        message += data

        self.key.verify(signature[8:], message)


class Vkey:
    def __init__(self, name: str, key_id: Optional[int], sig_type: int, pubkey: bytes):
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
            case _:
                raise NotImplementedError(f'unsupported signature type {self.sig_type} for verification')


class VkeySet:
    def __init__(self, *args: Vkey):
        self.keys: dict[tuple[str, int], Vkey] = {}

        for arg in args:
            self.add(arg)

    def add(self, vkey: Vkey) -> None:
        self.keys[(vkey.name, vkey.key_id)] = vkey

    def verify(self, sigs: Iterable[NoteSignature], data: bytes) -> set[tuple[Vkey, NoteSignature]]:
        valid = set()

        for sig in sigs:
            vkey = self.keys.get((sig.name, sig.key_id))
            if vkey is None:
                continue

            verifier = vkey.get_verifier()
            try:
                verifier.verify_note(sig, data)
                valid.add((vkey, sig))
            except Exception as e:
                logger.warning(f'verifying {sig} on {data.hex()} and vkey {vkey} failed', exc_info=e)

        return valid
