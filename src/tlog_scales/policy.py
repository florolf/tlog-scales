from collections import OrderedDict, defaultdict
from typing import Self, cast

from .signing import CosignatureVerifier, NoteSignature, Vkey
from .tlog import Checkpoint
from .utils import sha256


class QuorumUnsatisfiedError(Exception):
    pass


class Quorum:
    def __init__(self, timestamp: int):
        self.timestamp = timestamp


class Policy:
    def __init__(self, logs: list[tuple[Vkey, str|None]], entities: OrderedDict[str, Vkey | tuple[int, set[str]]], entry_point: str | None):
        self.logs = logs
        self.entities = entities
        self.entry_point = entry_point

        self.witness_names: dict[tuple[str, int], str] = {}
        for name, entity in entities.items():
            if isinstance(entity, Vkey):
                self.witness_names[entity.identity()] = name

    @staticmethod
    def _parse_key(key: str, witness: bool, sigsum: bool | None = None) -> tuple[Vkey, bool]:
        if sigsum is False:
            return (Vkey.from_string(key), False)

        try:
            pubkey = bytes.fromhex(key)
            if len(pubkey) != 32:
                raise ValueError(f'{key} is the wrong length for an Ed25519 pubkey')

            keyhash = sha256(pubkey).hex()
            if witness:
                name = f'sigsum.org/v1/witness/{keyhash}'
                key_type = 4
            else:
                name = f'sigsum.org/v1/tree/{keyhash}'
                key_type = 1

            return (Vkey(name, None, key_type, pubkey), True)
        except ValueError:
            if sigsum is True:
                raise

            return (Vkey.from_string(key), False)

    @classmethod
    def from_text(cls, policy: str, is_sigsum: bool | None = None) -> Self:
        entry_point = None
        entities = OrderedDict()
        logs = []
        witness_pubkeys = {}

        for line in policy.splitlines():
            if line.startswith('#'):
                continue

            match line.split():
                case ['log', pubkey, *_url] if len(_url) <= 1:
                    vkey, is_sigsum = cls._parse_key(pubkey, False, is_sigsum)
                    logs.append((vkey, _url[0] if _url else None))

                case ['witness', name, pubkey, *_]:
                    if name == 'none':
                        raise ValueError('quorum entity name "none" is reserved')

                    if name in entities:
                        raise ValueError(f'quorum entity "{name}" already exists')

                    vkey, is_sigsum = cls._parse_key(pubkey, True, is_sigsum)
                    try:
                        verifier = vkey.get_verifier()
                    except NotImplementedError:
                        verifier = None

                    if not isinstance(verifier, CosignatureVerifier):
                        raise ValueError(f'vkey {pubkey} ({vkey}) does not correspond to a cosignature verifier')  # noqa: TRY004

                    if (other := witness_pubkeys.get(vkey.key_params())) is not None:
                        raise ValueError(f'witness "{name}" duplicates the public key of witness "{other}"')

                    witness_pubkeys[vkey.key_params()] = name
                    entities[name] = vkey

                case ['group', name, threshold, *members]:
                    if name == 'none':
                        raise ValueError('quorum entity name "none" is reserved')

                    if name in entities:
                        raise ValueError(f'quorum entity "{name}" already exists')

                    if len(members) == 0:
                        raise ValueError(f'group "{name}" has no members')

                    if len(set(members)) != len(members):
                        raise ValueError(f'group "{name}" has duplicate members')

                    if threshold == 'all':
                        threshold = len(members)
                    elif threshold == 'any':
                        threshold = 1
                    else:
                        threshold = int(threshold)
                        if not (1 <= threshold <= len(members)):
                            raise ValueError(f'group "{name}" has invalid threshold')

                    for member in members:
                        if member not in entities:
                            raise ValueError(f'group "{name}" refers to unknown entity "{member}"')

                    entities[name] = (threshold, set(members))

                case ['quorum', _entry_point]:
                    if entry_point is not None:
                        raise ValueError('multiple quorum definitions in policy')

                    entry_point = _entry_point

        if entry_point is None:
            raise ValueError('quorum not specified')

        if entry_point == 'none':
            return cls(logs, entities, None)
        else:
            if entry_point not in entities:
                raise ValueError(f'quorum entry point "{entry_point}" is unknown')

            return cls(logs, entities, entry_point)

    def check(self, cp: Checkpoint, strict: bool = False) -> Quorum:
        cosignatures: dict[int, set[tuple[str, CosignatureVerifier, NoteSignature]]] = defaultdict(set)
        for signature in cp.signatures:
            if (name := self.witness_names.get((signature.name, signature.key_id))) is not None:
                witness = cast(Vkey, self.entities[name])
                verifier = cast(CosignatureVerifier, witness.get_verifier())
                timestamp = verifier.get_timestamp(signature.payload)

                cosignatures[timestamp].add((name, verifier, signature))

        if self.entry_point is None:
            if cosignatures:
                timestamp = max(cosignatures.keys())
            else:
                timestamp = 0

            return Quorum(timestamp)

        good: set[str] = set()
        for timestamp in sorted(cosignatures.keys(), reverse=True):
            for name, verifier, signature in cosignatures[timestamp]:
                try:
                    verifier.verify_note(signature, cp)
                except Exception:
                    if strict:
                        raise
                    else:
                        continue

                good.add(name)

            # Because the input policy is already topologically sorted (you can
            # only refer to entities that are already defined), we can just make a
            # single pass and collect all the groups that are satisfied as we go.
            for name, entity in self.entities.items():
                if isinstance(entity, tuple):
                    cardinality, members = entity
                    if len(members & good) >= cardinality:
                        good.add(name)

            if self.entry_point in good:
                return Quorum(timestamp)

        raise QuorumUnsatisfiedError()
