import dataclasses
from textwrap import dedent
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey

from tlog_scales.policy import Policy, QuorumUnsatisfiedError
from tlog_scales.signing import (
    Ed25519CosignatureSigner,
    MLDSA44CosignatureSigner,
    NoteSignature,
    PlainEd25519Signer,
    SignatureInvalid,
    Vkey,
)
from tlog_scales.tlog import Checkpoint
from tlog_scales.utils import sha256

SIGSUM_TEST_2025_3 = '''\
# Policy using two sigsum test logs at test.sigsum.org/barreleye and serviceberry.tlog.stagemole.eu

log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye
log 47e481606d8acba747a6b053d6c2d191605fb122175d410a1202a91430abce39 https://serviceberry.tlog.stagemole.eu

# Test witness operated by Niels Möller running on a Glasklar Teknik server
witness poc.sigsum.org/nisse                       1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c

# Test witness operated by Rasmus Dahlberg - https://www.rgdd.se/poc-witness/about
witness rgdd.se/poc-witness                        28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

# Test witness operated by Elias Rudberg - https://witness1.smartit.nu/witness1/about.txt
witness witness1.smartit.nu/witness1               f4855a0f46e8a3e23bb40faf260ee57ab8a18249fa402f2ca2d28a60e1a3130e

# Staging witness operated by Filippo Valsorda - https://navigli.sunlight.geomys.org/
witness witness.navigli.sunlight.geomys.org        dcbf728e02d479f5a7e20dc09adf525833ed6e797526517aeb07fc6854849fc6

# Test witness operated by Florian Larysch - https://remora.n621.de/
witness remora.n621.de                             ebcdeb78e7fdb2ef9227b2c1ef11e94600b55b4d6d9a57877e31ee89e59adc36

# Test witness operated by Mullvad VPN AB - https://witness.stagemole.eu/about
witness witness.stagemole.eu                       4a921b7caef58ae670cdc11ef4184f1c058f7b9259a9107a969f69fa54aa496f

# Test witness operated by Tillitis AB - new key since October 2025
witness tillitis.se/test-witness-1                 636582aec12f32c18a21733db9e3f718058ee7aaec6dbe4eb81781e0f4300c6e

# Test witness operated by Google TrustFabric team - https://transparency.dev/witnesses/
witness transparency.dev/DEV:witness-little-garden 2b6eb0ec483503544cde4e8fc1ce6d1921db21dffccc186865f808f7625443cc

# Group of 3 witnesses that are all run by Glasklar employees
group glasklar-test-witnesses 2 poc.sigsum.org/nisse rgdd.se/poc-witness witness1.smartit.nu/witness1

# Requiring 4 of 6 is intended to give reasonable reliability.
group quorum-rule 4 glasklar-test-witnesses witness.navigli.sunlight.geomys.org remora.n621.de witness.stagemole.eu tillitis.se/test-witness-1 transparency.dev/DEV:witness-little-garden

quorum quorum-rule
'''


BARRELEYE_CHECKPOINT = '''\
sigsum.org/v1/tree/4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d
277403
NseHoUzqki3Y9CRDaFqXb8SBA/LDaeW/NkiYXTSAA64=

— sigsum.org/v1/tree/4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d d4YpseT4KKA2QJ84gHqo2ZycqfotsDJAPP2ZklJCAHZVbe/BkRF+2+BAvJn9Ir0Pb04pBGcFEbn+H3VhNhWMf7luIgY=
— poc.sigsum.org/nisse rDC+YQAAAABq9GMUkuQ+iFue8BOFeUqdCmQCtjR94y7/mpk1ZzJ1NJRoyq545zZXW+8eLHhqfWIC2sLMcsWg4tJs+aJ0uMCpjW7uCg==
— witness.stagemole.eu Z/euoAAAAABq9GMU0eN42e8bsGo8e/zczGHP/1Njp1COJnIgvhgCUoRV2wfQ9Q9U3OLiZlnjzs9Oa/ResQF239qU0U+MjQjFpJvGBQ==
— witness1.smartit.nu/witness1 pIyCDwAAAABq9GMUfYNd4cmMnTOHX645Z98i1WfrigHYblxzS8b0qPExd9dXmHxCC/mj5m5tKRSYasBrzgRMXD9o0mj44CDSPztqDg==
— remora.n621.de 2net5wAAAABq9GMUq2B2698Ztyms09DLwRHoxgEUGZlzLg1zADiu3OO+/6m/m2EN/g7a2UgOhe9JE976UX7Eo//0VLIOLoLSmY/EDQ==
— transparency.dev/DEV:witness-little-garden 2AQqhwAAAABq9GMU4tIDquwka7hvO3pucfVmkHBrjqRxwXvDHPG1hImeE/Li5ylx9AUOKYXPaStaf2hqB1NhBmmOzp3CesTafla/CQ==
— tillitis.se/test-witness-1 cifk5wAAAABq9GMU95Y8CuNm7ZDI3aFDObP9Qf9zC2jHoqLb77PNTT+VlJh55nIrYMUznEaoL1Y4X36nspHAG+umXxBq/OvX4UMyDw==
— rgdd.se/poc-witness 2wNzLgAAAABq9GMUrYJYDKUe2LdZe04l2lyWOo0lcDnphwufD6EVFvyXRseY8Dl5Whw7FpHonJn2kTbU9wRmBl6yEUlyaosh9+OnDg==
— witness.navigli.sunlight.geomys.org o+AP4gAAAABq9GMUXW9Ii3viUupCighn7U9d0cEjh/TmaeVZtV3kpBvx+S88I2OQ+2m7FpFJ7aiPuWs0h+0wgGi3vzzaRsIZB2+mBg==
'''


def drop_cosignatures(cp: Checkpoint, policy: Policy, *witnesses: str) -> Checkpoint:
    drop = set()
    for witness in witnesses:
        entity = policy.entities[witness]
        assert isinstance(entity, Vkey)
        drop.add(entity.identity())
    sigs = [s for s in cp.signatures if (s.name, s.key_id) not in drop]
    return dataclasses.replace(cp, signatures=sigs)


def ed25519_witness(name: str) -> Ed25519CosignatureSigner:
    return Ed25519CosignatureSigner(name, Ed25519PrivateKey.generate())


def cosign(signer: Ed25519CosignatureSigner | MLDSA44CosignatureSigner, cp: Checkpoint, timestamp: int) -> NoteSignature:
    with mock.patch('tlog_scales.signing.time.time', return_value=timestamp):
        return signer.sign(cp)


def witness_lines(*signers: Ed25519CosignatureSigner | MLDSA44CosignatureSigner) -> str:
    return ''.join(f'witness {s.vkey.name} {s.vkey.serialize()}\n' for s in signers)


def sigsum_pubkey() -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()


CP = Checkpoint('example.com/log', 42, sha256(b'root'), [])


class TestParsing:
    def test_sigsum_logs(self) -> None:
        policy = Policy.from_text(SIGSUM_TEST_2025_3)

        assert [url for _, url in policy.logs] == [
            'https://test.sigsum.org/barreleye',
            'https://serviceberry.tlog.stagemole.eu'
        ]

        key, _ = policy.logs[0]
        converted = Vkey.from_string('sigsum.org/v1/tree/4e89cc51651f0d95f3c6127c15e1a42e3ddf7046c5b17b752689c402e773bb4d+778629b1+AUZEryq9QPSJWgA7yjUPnVkSqzAaScd/E+W22QXCCl/m')
        assert key == converted

    def test_vkey_logs(self) -> None:
        a = PlainEd25519Signer('example.com/a', Ed25519PrivateKey.generate())
        b = PlainEd25519Signer('example.com/b', Ed25519PrivateKey.generate())

        policy = Policy.from_text(
            f'log {a.vkey.serialize()}\n'
            f'log {b.vkey.serialize()} https://b.example.com\n'
            'quorum none\n'
        )

        assert policy.logs == [(a.vkey, None), (b.vkey, 'https://b.example.com')]

    @pytest.mark.parametrize('threshold, expected', [('any', 1), ('all', 3)])
    def test_group_threshold_keywords(self, threshold: str, expected: int) -> None:
        policy = Policy.from_text(
            f'witness a {sigsum_pubkey()}\n'
            f'witness b {sigsum_pubkey()}\n'
            f'witness c {sigsum_pubkey()}\n'
            f'group g {threshold} a b c\n'
            'quorum g\n'
        )

        assert policy.entities['g'] == (expected, {'a', 'b', 'c'})

    @pytest.mark.parametrize('policy', [
        pytest.param('witness a {k1}\n', id='no-quorum'),
        pytest.param('witness a {k1}\nquorum a\nquorum a\n', id='multiple-quorums'),
        pytest.param('witness a {k1}\nquorum b\n', id='unknown-entry-point'),
        pytest.param('witness a {k1}\nwitness a {k2}\nquorum a\n', id='duplicate-witness-name'),
        pytest.param('witness a {k1}\ngroup a any a\nquorum a\n', id='group-shadows-witness'),
        pytest.param('witness a {k1}\nwitness b {k1}\nquorum a\n', id='duplicate-witness-key'),
        pytest.param('witness none {k1}\nquorum none\n', id='reserved-witness-name'),
        pytest.param('witness a {k1}\ngroup none any a\nquorum a\n', id='reserved-group-name'),
        pytest.param('witness a {k1}\ngroup g any\nquorum g\n', id='empty-group'),
        pytest.param('witness a {k1}\nwitness b {k2}\ngroup g all a b b\nquorum g\n', id='duplicate-member'),
        pytest.param('witness a {k1}\ngroup g any a b\nquorum g\n', id='unknown-member'),
        pytest.param(
            'witness a {k1}\ngroup g any a b\nwitness b {k2}\nquorum g\n',
            id='forward-reference',
        ),
        pytest.param('witness a {k1}\nwitness b {k2}\ngroup g 0 a b\nquorum g\n', id='threshold-zero'),
        pytest.param('witness a {k1}\nwitness b {k2}\ngroup g 3 a b\nquorum g\n', id='threshold-too-large'),
        pytest.param('witness a {k1}\nwitness b {k2}\ngroup g most a b\nquorum g\n', id='threshold-garbage'),
    ])
    def test_invalid_structure(self, policy: str) -> None:
        with pytest.raises(ValueError):
            Policy.from_text(policy.format(k1=sigsum_pubkey(), k2=sigsum_pubkey()))

    def test_mixed_key_formats_rejected(self) -> None:
        # A policy is either sigsum-style (hex keys) or vkey-style, never both.
        vkey = ed25519_witness('example.com/w').vkey.serialize()

        with pytest.raises(ValueError):
            Policy.from_text(f'witness a {sigsum_pubkey()}\nwitness b {vkey}\nquorum a\n')

        with pytest.raises(ValueError):
            Policy.from_text(f'witness a {vkey}\nwitness b {sigsum_pubkey()}\nquorum a\n')

    def test_witness_requires_cosignature_key(self) -> None:
        # A plain Ed25519 note key (as used by logs) can't produce cosignatures.
        log = PlainEd25519Signer('example.com/log', Ed25519PrivateKey.generate())

        with pytest.raises(ValueError, match='cosignature'):
            Policy.from_text(f'witness a {log.vkey.serialize()}\nquorum a\n')


class TestQuorumRealWorld:
    def test_nested_groups(self) -> None:
        policy = Policy.from_text(SIGSUM_TEST_2025_3)
        cp = Checkpoint.from_text(BARRELEYE_CHECKPOINT)

        assert policy.check(cp).timestamp == 1794401044

        # The Glasklar group still holds with one member gone, and the
        # top-level rule tolerates losing two of its six members.
        policy.check(drop_cosignatures(
            cp, policy,
            'poc.sigsum.org/nisse',
            'remora.n621.de',
            'witness.stagemole.eu',
        ))

        # Losing a second Glasklar member takes out the whole group, which
        # together with two other missing witnesses drops below 4.
        with pytest.raises(QuorumUnsatisfiedError):
            policy.check(drop_cosignatures(
                cp, policy,
                'poc.sigsum.org/nisse',
                'rgdd.se/poc-witness',
                'remora.n621.de',
                'witness.stagemole.eu',
            ))


def test_strict_rejects_invalid_cosignature() -> None:
    witness = ed25519_witness('example.com/witness')
    policy = Policy.from_text(witness_lines(witness) + f'quorum {witness.vkey.name}\n')
    other = dataclasses.replace(CP, size=CP.size + 1)
    cp = dataclasses.replace(CP, signatures=[cosign(witness, other, 1000)])

    with pytest.raises(SignatureInvalid):
        policy.check(cp, strict=True)


class TestQuorum:
    CHECKPOINT = '''\
sigsum.org/v1/tree/44ad38f8226ff9bd27629a41e55df727308d0a1cd8a2c31d3170048ac1dd22a1
32692
QVHjDWWN5XX6NOJjZvNSL0fbqH3QbM6iCLzVxcgafEQ=

— seasalp.glasklar.is qJgFLmrQsQcy/on7IPwGdedr2DE/E2v3E50ByMWkra4sH81EeOwKtszeI96W5vTsu9CMjUdY+hcPAAtu4Yyy6t4tOQQ=
— tillitis.se/tillitis-witness-1 kkZpSgAAAABptVHWkFctmBsh12Sx9Ybs+xMjg65GncWnREog1K5k11vNxMIRfVlg5wth0Pc4A8SX+BOgeziuitPL2cYOxMK47y6xDQ==
— witness.glasklar.is kK2A5gAAAABptVHWiIdVH4utwZr8B1qC2lYkY9yDVZmt+4R4ARKh1i/spFOuDlFyJtNwEe/LCfi4SX3+KTbN3mceQwKY/9nwJnTjAA==
— witness.mullvad.net DjXQTQAAAABptVHW/S0bV0v7U+aDuEsUdy1OD5j8MfNBAgWKuiRkOWhr6HZcDgNVsuxT1Uk0lKKCQs1IpVNwV9W7n7jOt1hUY7COAQ==
'''

    def test_none_quorum(self):
        quorum = Policy.from_text("quorum none")
        quorum.check(Checkpoint.from_text(self.CHECKPOINT))

    def test_witness_quorum(self):
        quorum = Policy.from_text(dedent("""
        witness witness.glasklar.is witness.glasklar.is+90ad80e6+BLIQbbkGXsl/JeCcGIOSFnUabibY7YtB5IWlY9PRSYU2
        quorum witness.glasklar.is
        """))
        quorum.check(Checkpoint.from_text(self.CHECKPOINT))

    def test_group_quorum(self):
        for size in range(1, 4):
            quorum = Policy.from_text(dedent(f"""
            witness witness.glasklar.is witness.glasklar.is+90ad80e6+BLIQbbkGXsl/JeCcGIOSFnUabibY7YtB5IWlY9PRSYU2
            witness witness.mullvad.net witness.mullvad.net+0e35d04d+BBXW0BQVQyR7dLqzwQdjctnIlPYZw3bWSymqMSzAD2Gt
            witness dummy               dummy+fb7c490e+BMkZwJ5FMrVl8ns7nrbXlL0+pyFiFXYTrAVJMpSlhHZW
            group group {size} witness.glasklar.is witness.mullvad.net dummy
            quorum group
            """))

            if size < 3:
                quorum.check(Checkpoint.from_text(self.CHECKPOINT))
            else:
                with pytest.raises(QuorumUnsatisfiedError):
                    quorum.check(Checkpoint.from_text(self.CHECKPOINT))

    def test_invalid_quorum_rule(self):
        policies = [
            # witness name collision
            ('already exists', """
            witness dummy              0000000000000000000000000000000000000000000000000000000000000000
            witness dummy              0000000000000000000000000000000000000000000000000000000000000000
            quorum dummy
            """),

            # group name collision
            ('already exists', """
            witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
            witness dummy2             1111111111111111111111111111111111111111111111111111111111111111

            group foo any dummy1
            group foo any dummy2
            quorum dummy1
            """),

            # witness/group name collision
            ('already exists', """
            witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
            group dummy1 any dummy1
            quorum dummy1
            """),

            # unknown group member
            ('unknown entity', """
            witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
            group group any dummy2
            quorum dummy1
            """),

            # empty group
            ('no member', """
            group group any
            quorum group
            """),

            # zero threshold
            ('invalid threshold', """
            witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
            group group 0 dummy1
            quorum dummy1
            """),

            # excessive threshold
            ('invalid threshold', """
            witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
            group group 2 dummy1
            quorum dummy1
            """),

            # multiple quorum lines
            ('multiple quorum', """
            witness dummy1             0000000000000000000000000000000000000000000000000000000000000000
            quorum dummy1

            witness dummy2             1111111111111111111111111111111111111111111111111111111111111111
            quorum dummy2
            """),

            # entity called "none"
            ('"none" is reserved', """
            witness none               0000000000000000000000000000000000000000000000000000000000000000
            quorum none
            """),

            # quorum missing
            ('quorum not specified', """
            witness dummy              0000000000000000000000000000000000000000000000000000000000000000
            """),
        ]

        for match, pol in policies:
            with pytest.raises(ValueError, match=match):
                Policy.from_text(dedent(pol))

    def test_invalid_cosignature(self):
        th = Checkpoint.from_text(dedent("""\
        sigsum.org/v1/tree/44ad38f8226ff9bd27629a41e55df727308d0a1cd8a2c31d3170048ac1dd22a1
        32692
        QVHjDWWN5XX6NOJjZvNSL0fbqH3QbM6iCLzVxcgafEQ=

        — seasalp.glasklar.is qJgFLmrQsQcy/on7IPwGdedr2DE/E2v3E50ByMWkra4sH81EeOwKtszeI96W5vTsu9CMjUdY+hcPAAtu4Yyy6t4tOQQ=
        — witness.glasklar.is kK2A5gAAAABJlgLSiIdVH4utwZr8B1qC2lYkY9yDVZmt+4R4ARKh1i/spFOuDlFyJtNwEe/LCfi4SX3+KTbN3mceQwKY/9nwJnTjAA==
        """))

        policy = Policy.from_text(dedent("""
        witness witness.glasklar.is witness.glasklar.is+90ad80e6+BLIQbbkGXsl/JeCcGIOSFnUabibY7YtB5IWlY9PRSYU2
        quorum witness.glasklar.is
        """))

        # we deliberately don't raise a crypto error here by default but rather
        # just ignore the witness, which should cause the quorum to fail
        with pytest.raises(QuorumUnsatisfiedError):
            policy.check(th)

        with pytest.raises(SignatureInvalid):
            policy.check(th, strict=True)


class TestQuorumTimestamps:
    """
    The quorum timestamp is the latest point in time at which the policy was
    satisfied, i.e. the largest T such that the valid cosignatures made at or
    after T satisfy the quorum.
    """

    def test_timestamp_is_when_quorum_was_reached(self) -> None:
        a, b, c = (ed25519_witness(f'example.com/{n}') for n in 'abc')
        policy = Policy.from_text(witness_lines(a, b, c) + f'group q 2 {a.vkey.name} {b.vkey.name} {c.vkey.name}\nquorum q\n')

        cp = dataclasses.replace(CP, signatures=[
            cosign(a, CP, 1000),
            cosign(b, CP, 2000),
            cosign(c, CP, 3000),
        ])

        # c alone (at 3000) is not enough, c+b (at 2000) is.
        assert policy.check(cp).timestamp == 2000

    def test_invalid_cosignature_is_ignored(self) -> None:
        a, b, c = (ed25519_witness(f'example.com/{n}') for n in 'abc')
        policy = Policy.from_text(witness_lines(a, b, c) + f'group q 2 {a.vkey.name} {b.vkey.name} {c.vkey.name}\nquorum q\n')

        other = dataclasses.replace(CP, size=CP.size + 1)
        cp = dataclasses.replace(CP, signatures=[
            cosign(a, CP, 1000),
            cosign(b, CP, 2000),
            cosign(c, other, 3000),  # valid signature, but not for this checkpoint
        ])

        assert policy.check(cp).timestamp == 1000

    def test_unknown_witnesses_are_ignored(self) -> None:
        a = ed25519_witness('example.com/a')
        stranger = ed25519_witness('example.com/stranger')
        # Same name as a, but a different key.
        impostor = ed25519_witness('example.com/a')

        policy = Policy.from_text(witness_lines(a) + f'quorum {a.vkey.name}\n')

        cp = dataclasses.replace(CP, signatures=[
            cosign(a, CP, 1000),
            cosign(stranger, CP, 2000),
            cosign(impostor, CP, 3000),
        ])
        assert policy.check(cp).timestamp == 1000

        with pytest.raises(QuorumUnsatisfiedError):
            policy.check(dataclasses.replace(cp, signatures=cp.signatures[1:]))

    def test_mixed_signature_algorithms(self) -> None:
        ed = ed25519_witness('example.com/ed25519-witness')
        pq = MLDSA44CosignatureSigner('example.com/mldsa-witness', MLDSA44PrivateKey.generate())
        policy = Policy.from_text(witness_lines(ed, pq) + f'group q all {ed.vkey.name} {pq.vkey.name}\nquorum q\n')

        cp = dataclasses.replace(CP, signatures=[cosign(ed, CP, 1000), cosign(pq, CP, 2000)])
        assert policy.check(cp).timestamp == 1000

        with pytest.raises(QuorumUnsatisfiedError):
            policy.check(dataclasses.replace(cp, signatures=cp.signatures[:1]))

    def test_quorum_none(self) -> None:
        a = ed25519_witness('example.com/a')
        policy = Policy.from_text(witness_lines(a) + 'quorum none\n')

        assert policy.check(CP).timestamp == 0

        cp = dataclasses.replace(CP, signatures=[cosign(a, CP, 1000)])
        assert policy.check(cp).timestamp == 1000


class TestSerialization:
    def test_roundtrip(self) -> None:
        log_a = PlainEd25519Signer('example.com/log-a', Ed25519PrivateKey.generate())
        log_b = PlainEd25519Signer('example.com/log-b', Ed25519PrivateKey.generate())
        a, b, c = (ed25519_witness(f'example.com/{n}') for n in 'abc')

        policy = Policy.from_text(
            f'log {log_a.vkey.serialize()}\n'
            f'log {log_b.vkey.serialize()} https://b.example.com\n'
            + witness_lines(a, b, c)
            + f'group g-any any {a.vkey.name} {b.vkey.name}\n'
            + f'group g-all all {b.vkey.name} {c.vkey.name}\n'
            + f'group g-2 2 g-any g-all {c.vkey.name}\n'
            + 'quorum g-2\n'
        )
        reparsed = Policy.from_text(policy.serialize())

        assert reparsed.logs == policy.logs
        assert reparsed.entities == policy.entities
        assert reparsed.entry_point == policy.entry_point

    def test_roundtrip_sigsum(self) -> None:
        policy = Policy.from_text(SIGSUM_TEST_2025_3)
        reparsed = Policy.from_text(policy.serialize())

        assert reparsed.logs == policy.logs
        assert reparsed.entities == policy.entities
        assert reparsed.entry_point == policy.entry_point

        cp = Checkpoint.from_text(BARRELEYE_CHECKPOINT)
        assert reparsed.check(cp).timestamp == policy.check(cp).timestamp

    def test_empty(self) -> None:
        assert Policy.from_text('quorum none\n').serialize() == 'quorum none'
