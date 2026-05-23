from dataclasses import dataclass
from typing import Self

from . import signing
from .utils import b64enc, b64dec, sha256

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

    def serialize(self, with_signatures: bool = True) -> str:
        checkpoint = self._serialize_body(self.origin, self.size, self.root_hash)
        if not with_signatures:
            return checkpoint

        checkpoint += "\n"
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

    def verify(self, vkey: signing.Vkey):
        data = self.serialize(with_signatures=False).encode()

        for sig in self.signatures:
            if vkey.match(sig):
                vkey.get_verifier().verify(sig.payload, data)
                return

        raise RuntimeError('no signature matched vkey')


class ConsistencyProofInvalid(Exception):
    pass


@dataclass(frozen=True)
class ConsistencyProof:
    old_size: int
    new_size: int

    node_hashes: list[bytes]

    def __str__(self):
        hashes = ", ".join([x.hex() for x in self.node_hashes])
        return f"ConsistencyProof(old_size={self.old_size}, new_size={self.new_size}, node_hashes=[{hashes}])"

    def check(self, old_hash: bytes, new_hash: bytes):
        # This function is a literal translation of RFC 9162, section 2.1.4.2.
        # "Verifying Consistency between Two Tree Heads", except for the
        # following block.
        #
        # We add this since the RFC verification algorithm has the precondition
        # 0 < old_size < new_size, which implies that there is something to
        # prove. However there are two trivial cases that still make sense to
        # consider here for consistency even though they don't happen in real
        # Sigsum protocol interactions:
        #
        #  - old_size == new_size and old_hash == new_hash, i.e. a tree head is
        #    consistent with itself
        #
        #  - an empty tree (old_size == 0, old_hash = MTH({}) = HASH()) is
        #    consistent with everything
        #
        # In those cases, there is nothing to prove and thus node_hashes is
        # empty.

        if not self.node_hashes:
            if self.old_size == self.new_size and old_hash == new_hash:
                return

            if self.old_size == 0 and old_hash == sha256(b''):
                return

        if not (0 < self.old_size < self.new_size):
            raise ConsistencyProofInvalid(f'0 < old_size ({self.old_size}) < new_size ({self.new_size}) violated')

        # RFC names and logic from here on
        consistency_path = self.node_hashes.copy()
        first = self.old_size
        second = self.new_size
        first_hash = old_hash
        second_hash = new_hash

        # 1. If consistency_path is an empty array, stop and fail the proof
        # verification.
        if not consistency_path:
            raise ConsistencyProofInvalid('consistency_path is empty')

        # 2. If first is an exact power of 2, then prepend first_hash to the
        # consistency_path array.
        if first & (first - 1) == 0:
            consistency_path.insert(0, first_hash)

        # 3. Set fn to first - 1 and sn to second - 1.
        fn = first - 1
        sn = second - 1

        # 4. If LSB(fn) is set, then right-shift both fn and sn equally until
        # LSB(fn) is not set.
        while (fn & 1) != 0:
            fn >>= 1
            sn >>= 1

        # 5. Set both fr and sr to the first value in the consistency_path
        # array.
        fr = consistency_path[0]
        sr = consistency_path[0]

        # 6. For each subsequent value c in the consistency_path array:
        for c in consistency_path[1:]:
            # a. If sn is 0, then stop the iteration and fail the proof
            # verification.
            if sn == 0:
                raise ConsistencyProofInvalid('sn == 0 with consitency_path entries remaining')

            # b. If LSB(fn) is set, or if fn is equal to sn, then:
            if (fn & 1) == 1 or fn == sn:
                # i. Set fr to HASH(0x01 || c || fr).
                fr = sha256(b'\x01' + c + fr)

                # ii. Set sr to HASH(0x01 || c || sr).
                sr = sha256(b'\x01' + c + sr)

                # iii. If LSB(fn) is not set, then right-shift both fn and sn
                # equally until either LSB(fn) is set or fn is 0.
                if (fn & 1) == 0:
                    while True:
                        fn >>= 1
                        sn >>= 1

                        if (fn & 1) == 1 or fn == 0:
                            break
            # Otherwise:
            else:
                # i. Set sr to HASH(0x01 || sr || c).
                sr = sha256(b'\x01' + sr + c)

            # c. Finally, right-shift both fn and sn one time.
            fn >>= 1
            sn >>= 1

        # 7. After completing iterating through the consistency_path array as
        # described above, verify that the fr calculated is equal to the
        # first_hash supplied, that the sr calculated is equal to the
        # second_hash supplied, and that sn is 0.
        if fr != first_hash:
            raise ConsistencyProofInvalid(f'fr ({fr.hex()}) != first_hash ({first_hash.hex()})')

        if sr != second_hash:
            raise ConsistencyProofInvalid(f'fr ({sr.hex()}) != first_hash ({second_hash.hex()})')

        if sn != 0:
            raise ConsistencyProofInvalid(f'sn ({sn}) != 0 at the end of consistency_path')


class InclusionProofInvalid(Exception):
    pass


@dataclass(frozen=True)
class InclusionProof:
    leaf_index: int
    tree_size: int
    node_hashes: list[bytes]

    def __str__(self):
        hashes = ", ".join([x.hex() for x in self.node_hashes])
        return f"InclusionProof(leaf_index={self.leaf_index}, node_hashes=[{hashes}]"

    def check(self, leaf_hash: bytes, root_hash: bytes):
        # RFC 9162, section 2.1.3.2

        # 1. Compare leaf_index from the inclusion_proof_v2 structure against
        # tree_size. If leaf_index is greater than or equal to tree_size, then
        # fail the proof verification.

        if self.leaf_index >= self.tree_size:
            raise InclusionProofInvalid(f'leaf_index ({self.leaf_index}) < tree_size ({self.tree_size}) violated')

        # 2. Set fn to leaf_index and sn to tree_size - 1.
        fn = self.leaf_index
        sn = self.tree_size - 1

        # 3. Set r to hash.
        r = leaf_hash

        # 4. For each value p in the inclusion_path array:
        for p in self.node_hashes:
            # a. If sn is 0, then stop the iteration and fail the proof verification.
            if sn == 0:
                raise InclusionProofInvalid('sn == 0 with inclusion_path entries remaining')

            # b. If LSB(fn) is set, or if fn is equal to sn, then:
            if fn & 1 or fn == sn:

                # i. Set r to HASH(0x01 || p || r).
                r = sha256(b'\x01' + p + r)

                # ii. If LSB(fn) is not set, then right-shift both fn and sn
                # equally until either LSB(fn) is set or fn is 0.
                if fn & 1 == 0:
                    while True:
                        fn >>= 1
                        sn >>= 1

                        if fn & 1 != 0 or fn == 0:
                            break
                # Otherwise:
            else:
                # i. Set r to HASH(0x01 || r || p).
                r = sha256(b'\x01' + r + p)

            # c. Finally, right-shift both fn and sn one time. 
            fn >>= 1
            sn >>= 1

        # 5. Compare sn to 0. Compare r against the root_hash. If sn is equal
        # to 0 and r and the root_hash are equal, then the log has proven the
        # inclusion of hash. Otherwise, fail the proof verification.

        if sn != 0:
            raise InclusionProofInvalid(f'sn ({sn}) != 0 at the end of inclusion_path')

        if r != root_hash:
            raise InclusionProofInvalid(f'r ({r.hex()}) != root_hash ({root_hash.hex()})')
