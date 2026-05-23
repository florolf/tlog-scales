from dataclasses import dataclass
from typing import Protocol, Self

from .utils import b64enc, b64dec, sha256

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


class NoteSigner(Protocol):
    def sign(self, data: bytes) -> NoteSignature:
        ...

class DummySigner:
    def sign(self, data: bytes) -> NoteSignature:
        return NoteSignature('dummy', 0, sha256(data))
