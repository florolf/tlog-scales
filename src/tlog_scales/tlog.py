from dataclasses import dataclass
from typing import Self

from . import signing
from .utils import b64enc, b64dec

@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root_hash: bytes

    signatures: list[signing.NoteSignature]

    def __post_init__(self):
        if not self.signatures:
            raise ValueError('checkpoints need at least one signature')

    def __str__(self):
        signatures = [str(x) for x in self.signatures]
        return f"Checkpoint(origin={self.origin}, size={self.size}, root_hash={self.root_hash.hex()}, signatures=[{','.join(signatures)}])"

    @staticmethod
    def _serialize_body(origin: str, size: int, root_hash: bytes) -> str:
        return f"{origin}\n{size}\n{b64enc(root_hash)}\n"

    def serialize(self) -> str:
        checkpoint = self._serialize_body(self.origin, self.size, self.root_hash) + "\n"
        for sig in self.signatures:
            checkpoint += f'{sig.serialize()}\n'

        return checkpoint

    @classmethod
    def from_text(cls, text: str) -> Self:
        lines = text.splitlines()

        origin = lines[0]
        tree_size = int(lines[1])
        root_hash = b64dec(lines[2])
        signatures = [signing.NoteSignature.from_line(x) for x in lines[4:]]

        return cls(origin, tree_size, root_hash, signatures)

    @classmethod
    def make_signed(cls, origin: str, size: int, root_hash: bytes, signers: list[signing.NoteSigner]) -> Self:
        body = cls._serialize_body(origin, size, root_hash)

        signatures = []
        for signer in signers:
            signatures.append(signer.sign(body.encode()))

        return cls(origin, size, root_hash, signatures)


@dataclass(frozen=True)
class ConsistencyProof:
    old_size: int
    new_size: int

    node_hashes: list[bytes]

    def __str__(self):
        hashes = ", ".join([x.hex() for x in self.node_hashes])
        return f"ConsistencyProof(old_size={self.old_size}, new_size={self.new_size}, node_hashes=[{hashes}])"


@dataclass(frozen=True)
class InclusionProof:
    leaf_index: int
    tree_size: int
    node_hashes: list[bytes]

    def __str__(self):
        hashes = ", ".join([x.hex() for x in self.node_hashes])
        return f"InclusionProof(leaf_index={self.leaf_index}, node_hashes=[{hashes}]"
