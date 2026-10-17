"""
contracts.py — every interface in the capchain stack, in one place.

This file contains no implementation (except a few normative reference
bodies, marked as such).  It defines:

    - the value types that cross layer boundaries
    - the error taxonomy that every layer shares
    - the conventions (R1..R8) that bind every layer
    - the protocols each layer must satisfy
    - the module-level constants those types and protocols reference
    - normative reference bodies for the primitives two implementations
      must agree on byte-for-byte (link hash, canonical helpers)

Nothing here forces inheritance; every interface is structural.

Layer order, dependency direction (arrows point from consumer to
provider; nothing below depends on anything above):

"""

from __future__ import annotations

from enum import StrEnum
import hashlib
import re
from dataclasses import dataclass, field
from typing import (
    Any,
    Literal,
    Mapping,
    Optional,
    Protocol,
    Sequence,
    Union,
    runtime_checkable,
)


# ══════════════════════════════════════════════════════════════════════════
# §0  Conventions (R1..R8)
# ══════════════════════════════════════════════════════════════════════════
#
# R1  Verify the bytes you received.  A signature check runs over the wire
#     bytes as received, never over a re-encoding of a decoded view.
#     Every signed structure in this file stores its exact signed bytes
#     in a field named `body_raw`.  Typed accessors a caller wants are
#     available by decoding `body_raw` through a codec, never by
#     re-encoding a dataclass.
#
# R2  Fail closed.  If shared state is unavailable, the answer is
#     `deny, STATE_UNAVAILABLE`.  There is no degraded mode that allows.
#
# R3  Only `Reject` crosses a boundary.  `code` is stable; `detail` is
#     log-safe, printable-ASCII, and length-capped; never raise bare
#     Exception.  Values that are programming errors on in-memory data
#     (dataclass construction, thumbprint on a wrong-length byte string)
#     raise `ValueError`, not `Reject`.
#
# R4  kid := thumbprint := lowercase hex of sha256 over the 32-byte raw
#     Ed25519 public key.  One definition; every `kid` in this file means
#     exactly this.
#
# R5  Empty set means nothing.  ANY ("*") is the only wildcard, in any
#     Scope axis.  No empty-set-means-everywhere, anywhere.
#
# R6  @runtime_checkable is a debugging aid: isinstance() checks attribute
#     NAMES only, not signatures or types.  Never gate a trust decision on
#     an isinstance check against these protocols.
#
# R7  Time is Timestamp (POSIX seconds, UTC, int).  `now` is always an
#     explicit argument, supplied from a Clock.  No layer reads a clock
#     implicitly; no `now: Optional[...]` exists.
#
# R8  Verify cheap before expensive.  Size, depth, version, and field-
#     equality checks precede signature verification everywhere.


# ══════════════════════════════════════════════════════════════════════════
# §1  Constants, time, encoding
# ══════════════════════════════════════════════════════════════════════════

WIRE_VERSION: int = 1
"""Mandatory first field of every signed payload.  A verifier that does
not understand a version MUST raise VERSION_UNSUPPORTED, never attempt
to interpret the rest."""

Timestamp = int
"""POSIX seconds, UTC.  The only time type in this file."""

ANY = "*"
"""The only wildcard in Scope.  An empty frozenset means NOTHING, never
everything.  Using emptiness as 'unrestricted' is a silent attenuation
bypass on the parent side of is_subset_of."""

SIGNATURE_BYTES: int = 64
PUBLIC_KEY_BYTES: int = 32
THUMBPRINT_HEX_CHARS: int = 64
MAX_REJECT_DETAIL: int = 512
MAX_PIN_VALUE_BYTES: int = 4096
MAX_EVIDENCE_WINDOW: int = 10_000
MAX_FRAME_BYTES: int = 1 << 20
MAX_TOKEN_BYTES: int = 32 * 1024
MAX_BLOCKS: int = 16
MAX_AGENT_ID_CHARS: int = 255
MAX_CHANNEL_BINDING_BYTES: int = 32
MAX_SESSION_ID_CHARS: int = 128
MAX_NONCE_CHARS: int = 128
MAX_URI_CHARS: int = 512
MAX_JTI_CHARS: int = 128
MAX_RESOURCE_CHARS: int = 128
MAX_ACTION_CHARS: int = 128
MAX_PAYLOAD_HASH_CHARS: int = 71      # len("sha256:") + 64
GENESIS_PREV_HASH: str = "0" * 64
"""Sentinel for Block.prev_hash on block 0.  Not a hash of anything;
chosen so that it cannot collide with a real link hash (which is
sha256 hex of a non-empty byte string)."""


# Every domain label derives from WIRE_VERSION.  Bumping WIRE_VERSION
# MUST invalidate every label in the file simultaneously: a signature
# under an old label MUST NOT verify under a new one.
_WIRE: str = f"v{WIRE_VERSION}"


def ascii_safe(detail: Any) -> str:
    """Printable-ASCII, length-capped.  Handles non-str input by
    repr()ing it, so Reject(code, b"bytes") does not raise TypeError."""
    if not isinstance(detail, str):
        detail = repr(detail)
    cleaned = "".join(
        c if 0x20 <= ord(c) < 0x7F else "?"
        for c in detail
    )
    return cleaned[:MAX_REJECT_DETAIL]


def require_str(
    value: Any,
    name: str,
    *,
    min_len: int = 1,
    max_len: int,
    pattern: Optional[re.Pattern[str]] = None,
    err_cls: type = ValueError,
) -> str:
    """Shared string validation for dataclass __post_init__ and for
    PoPProof.build.  Raises err_cls with a message that names the
    field, the observed length, and the constraint violated."""
    if not isinstance(value, str):
        raise err_cls(f"{name} must be str, got {type(value).__name__}")
    if len(value) < min_len:
        raise err_cls(f"{name} too short: {len(value)} < {min_len}")
    if len(value) > max_len:
        raise err_cls(f"{name} too long: {len(value)} > {max_len}")
    if pattern is not None and not pattern.match(value):
        raise err_cls(f"{name} does not match {pattern.pattern!r}")
    return value


BLOCK_LINK_LABEL: bytes = f"capchain/{_WIRE}/block-link".encode("ascii")
"""Fixed domain label prefixed to the block link-hash input (see
Block).  Derived from WIRE_VERSION; a new wire version picks a new
label, and the label MUST NOT be reused across wire versions."""


class Alg(StrEnum):
    ED25519 = "ed25519"


class DocKind(StrEnum):
    MANIFEST = "manifest"
    ROSTER = "roster"
    FRESHNESS = "freshness"


class KeyStatus(StrEnum):
    ACTIVE = "active"
    RETIRING = "retiring"


class TransportKind(StrEnum):
    UNIX = "unix"
    TLS = "tls"


class Outcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class EvidenceLevel(StrEnum):
    VERIFIED = "verified"
    ASSERTED = "asserted"
    INFERRED = "inferred"


@runtime_checkable
class Clock(Protocol):
    """Injected time source.  Implementations of every other protocol
    take `now: Timestamp` from the caller; they never call this
    themselves.  Tests inject a fake; production injects wall time.
    """

    def now(self) -> Timestamp: ...


@dataclass(frozen=True, slots=True)
class SkewPolicy:
    """One place that defines 'close enough to now'.

    Invariant: `replay_ttl >= pop_max_age + max_future_skew`, or the
    replay window closes before a still-acceptable PoP expires and
    replay becomes possible again.  Construction MUST reject a policy
    that violates this.
    """

    max_future_skew: int = 30
    pop_max_age: int = 60
    replay_ttl: int = 300

    def __post_init__(self) -> None:
        if self.replay_ttl < self.pop_max_age + self.max_future_skew:
            raise ValueError(
                "replay_ttl must be >= pop_max_age + max_future_skew"
            )


def thumbprint(pub: bytes) -> str:
    """Lowercase hex sha256 of a 32-byte raw public key (R4).

    A module-level function, not a KeyResolver method: a derived value
    on an interface is a divergence bug waiting to happen.

    Preconditions:  `pub` is exactly PUBLIC_KEY_BYTES bytes.
    Postconditions: returns THUMBPRINT_HEX_CHARS lowercase hex chars.
    Raises:         ValueError on wrong-length input.  This is a
                    programming error on an in-memory value, not a
                    Reject: Reject is for untrusted input and for
                    boundary failures, and this is neither.
    """
    if not isinstance(pub, bytes) or len(pub) != PUBLIC_KEY_BYTES:
        raise ValueError(
            f"thumbprint requires {PUBLIC_KEY_BYTES} bytes, "
            f"got {len(pub) if isinstance(pub, bytes) else type(pub).__name__}"
        )
    return hashlib.sha256(pub).hexdigest()


@runtime_checkable
class Canonical(Protocol):
    """The one true byte encoding for anything that gets signed.

    The encoder is SCHEMA-AGNOSTIC.  It encodes exactly the mapping it
    is given.  It has no knowledge of which fields are optional and
    what their defaults are.  Every caller is responsible for
    supplying every field the schema names, with a default value for
    optional fields, BEFORE calling encode().

    Consequence, and this is the reason the rule is stated at the top:
    a caller that produces a payload differing from the accepted one
    only by the omission of an optional field creates a second signed
    form of the same logical claim.  Nothing in the encoder detects
    this.  Nothing in the verifier detects this, because the verifier
    decodes whatever the signer signed.  The only place this can be
    caught is a schema-aware caller that refuses to encode a mapping
    missing a required key.

    Contract:
      - encode() is injective: two distinct mappings never encode
        equal.  In particular, {k: ""} and {} encode differently, so
        an omitted field never collides with an empty one.
      - decode(encode(x)) == x for every x the encoder accepts.
      - encode(decode(b)) == b for every b the decoder accepts
        (no non-canonical form is accepted at all — reject, don't
        re-canonicalize).
      - Map keys are sorted by their encoded byte sequence.
      - Duplicate map keys are a decode error, never last-wins.
      - Integers are fixed-width; there are no floats anywhere in a
        signed payload.
      - Absent optional fields are encoded as the empty string / 0 /
        empty list by the *caller*, never omitted.
      - Decode of a non-canonical or unknown-version payload raises
        Reject(CANONICAL_FORM) or Reject(VERSION_UNSUPPORTED).
    """

    def encode(self, obj: Mapping[str, Any]) -> bytes: ...

    def decode(self, raw: bytes) -> Mapping[str, Any]: ...


class Code(StrEnum):
    OK = "OK"
    INTERNAL = "INTERNAL"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"
    ALG_UNSUPPORTED = "ALG_UNSUPPORTED"
    CANONICAL_FORM = "CANONICAL_FORM"

    SIGNER_UNAVAILABLE = "SIGNER_UNAVAILABLE"
    SIGNER_CLOSED = "SIGNER_CLOSED"
    SIGNER_MISMATCH = "SIGNER_MISMATCH"
    BAD_KEY_TYPE = "BAD_KEY_TYPE"
    KEY_UNKNOWN = "KEY_UNKNOWN"
    KEY_NOT_YET_VALID = "KEY_NOT_YET_VALID"
    KEY_EXPIRED = "KEY_EXPIRED"

    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_TIMEOUT = "SOURCE_TIMEOUT"
    SOURCE_EMPTY = "SOURCE_EMPTY"
    DOC_MALFORMED = "DOC_MALFORMED"
    DOC_SIGNATURE = "DOC_SIGNATURE"
    DOC_EXPIRED = "DOC_EXPIRED"
    DOC_NOT_YET_VALID = "DOC_NOT_YET_VALID"
    DOC_ROLLBACK = "DOC_ROLLBACK"
    DOC_EQUIVOCATION = "DOC_EQUIVOCATION"
    DOC_CONTEXT_DRIFT = "DOC_CONTEXT_DRIFT"
    DOC_CHAIN_BROKEN = "DOC_CHAIN_BROKEN"
    PIN_CORRUPT = "PIN_CORRUPT"
    PIN_STORE_UNAVAIL = "PIN_STORE_UNAVAIL"
    PIN_CONFLICT = "PIN_CONFLICT"
    ANCHOR_EXPIRED = "ANCHOR_EXPIRED"
    ANCHOR_INCONSISTENT = "ANCHOR_INCONSISTENT"

    TOKEN_MALFORMED = "TOKEN_MALFORMED"
    TOKEN_SIGNATURE = "TOKEN_SIGNATURE"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_NOT_YET_VALID = "TOKEN_NOT_YET_VALID"
    CHAIN_BROKEN = "CHAIN_BROKEN"
    HOLDER_MISMATCH = "HOLDER_MISMATCH"
    CONTEXT_DRIFT = "CONTEXT_DRIFT"
    SCOPE_WIDENED = "SCOPE_WIDENED"
    TOO_DEEP = "TOO_DEEP"
    TOKEN_TOO_LARGE = "TOKEN_TOO_LARGE"
    UNKNOWN_ISSUER = "UNKNOWN_ISSUER"

    NO_RULE = "NO_RULE"
    AMBIGUOUS_RULE = "AMBIGUOUS_RULE"
    WORKLOAD_DENIED = "WORKLOAD_DENIED"
    OPEN_RULE_REFUSED = "OPEN_RULE_REFUSED"

    TRANSPORT_UNKNOWN = "TRANSPORT_UNKNOWN"
    TRANSPORT_DENIED = "TRANSPORT_DENIED"
    HANDSHAKE_INCOMPLETE = "HANDSHAKE_INCOMPLETE"
    TLS_VERSION_LOW = "TLS_VERSION_LOW"
    VERIFY_MODE_UNSAFE = "VERIFY_MODE_UNSAFE"
    NO_PEER_CERT = "NO_PEER_CERT"
    CERT_MALFORMED = "CERT_MALFORMED"
    CERT_EXPIRED = "CERT_EXPIRED"
    CERT_NOT_YET_VALID = "CERT_NOT_YET_VALID"
    CERT_AMBIGUOUS = "CERT_AMBIGUOUS"
    SAN_MISSING = "SAN_MISSING"
    SAN_INVALID = "SAN_INVALID"
    SPKI_MISMATCH = "SPKI_MISMATCH"
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    UNKNOWN_CA = "UNKNOWN_CA"
    PEER_VANISHED = "PEER_VANISHED"
    PEER_REPLACED = "PEER_REPLACED"
    PEER_CREDS_CHANGED = "PEER_CREDS_CHANGED"
    PEER_EXE_UNREADABLE = "PEER_EXE_UNREADABLE"
    PROC_UNREADABLE = "PROC_UNREADABLE"
    NO_PEERCRED = "NO_PEERCRED"
    PIDFD_UNAVAILABLE = "PIDFD_UNAVAILABLE"

    POP_REQUIRED = "POP_REQUIRED"
    POP_MALFORMED = "POP_MALFORMED"
    POP_UNKNOWN_KEY = "POP_UNKNOWN_KEY"
    POP_MISMATCH = "POP_MISMATCH"
    POP_BAD_SIGNATURE = "POP_BAD_SIGNATURE"
    POP_STALE = "POP_STALE"
    POP_BINDING = "POP_BINDING"
    POP_REPLAY = "POP_REPLAY"
    CB_UNAVAILABLE = "CB_UNAVAILABLE"
    CB_MISMATCH = "CB_MISMATCH"

    REVOKED = "REVOKED"
    REPLAY = "REPLAY"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BUDGET_CAP_CHANGED = "BUDGET_CAP_CHANGED"
    STATE_UNAVAILABLE = "STATE_UNAVAILABLE"
    EVIDENCE_BROKEN = "EVIDENCE_BROKEN"

    POLICY_DENIED = "POLICY_DENIED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    WRONG_AUDIENCE = "WRONG_AUDIENCE"
    WRONG_SESSION = "WRONG_SESSION"
    WRONG_TASK = "WRONG_TASK"
    PEER_HOLDER_MISMATCH = "PEER_HOLDER_MISMATCH"
    TRUSTSET_EXPIRED = "TRUSTSET_EXPIRED"

    FRAME_MALFORMED = "FRAME_MALFORMED"
    FRAME_TOO_LARGE = "FRAME_TOO_LARGE"
    CONN_DEADLINE = "CONN_DEADLINE"

    SESSION_REQUIRED = "SESSION_REQUIRED"
    SESSION_INVALID = "SESSION_INVALID"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SESSION_PARENT_BAD = "SESSION_PARENT_BAD"
    SESSION_REVOKED = "SESSION_REVOKED"

    @property
    def layer(self) -> int:
        """Code -> layer mapping.  Log aggregation and alerting key on
        this, not on the numeric prefix in the name."""
        return _CODE_LAYER[self]

    @property
    def retryable(self) -> bool:
        """Default retryability for this code.  Raise sites MAY
        override per-Reject; callers use this to decide backoff,
        never to decide trust."""
        return self in _RETRYABLE


_CODE_LAYER: Mapping[Code, int] = {
    Code.OK: 0, Code.INTERNAL: 0,
    Code.VERSION_UNSUPPORTED: 0, Code.ALG_UNSUPPORTED: 0,
    Code.CANONICAL_FORM: 0,
    Code.SIGNER_UNAVAILABLE: 1, Code.SIGNER_CLOSED: 1,
    Code.SIGNER_MISMATCH: 1, Code.BAD_KEY_TYPE: 1, Code.KEY_UNKNOWN: 1,
    Code.KEY_NOT_YET_VALID: 1, Code.KEY_EXPIRED: 1,
    Code.SOURCE_UNAVAILABLE: 2, Code.SOURCE_TIMEOUT: 2, Code.SOURCE_EMPTY: 2,
    Code.DOC_MALFORMED: 2, Code.DOC_SIGNATURE: 2, Code.DOC_EXPIRED: 2,
    Code.DOC_NOT_YET_VALID: 2, Code.DOC_ROLLBACK: 2, Code.DOC_EQUIVOCATION: 2,
    Code.DOC_CONTEXT_DRIFT: 2, Code.DOC_CHAIN_BROKEN: 2,
    Code.PIN_CORRUPT: 2, Code.PIN_STORE_UNAVAIL: 2, Code.PIN_CONFLICT: 2,
    Code.ANCHOR_EXPIRED: 2, Code.ANCHOR_INCONSISTENT: 2,
    Code.TOKEN_MALFORMED: 3, Code.TOKEN_SIGNATURE: 3, Code.TOKEN_EXPIRED: 3,
    Code.TOKEN_NOT_YET_VALID: 3, Code.CHAIN_BROKEN: 3, Code.HOLDER_MISMATCH: 3,
    Code.CONTEXT_DRIFT: 3, Code.SCOPE_WIDENED: 3, Code.TOO_DEEP: 3,
    Code.TOKEN_TOO_LARGE: 3, Code.UNKNOWN_ISSUER: 3,
    Code.NO_RULE: 4, Code.AMBIGUOUS_RULE: 4, Code.WORKLOAD_DENIED: 4,
    Code.OPEN_RULE_REFUSED: 4,
    Code.TRANSPORT_UNKNOWN: 5, Code.TRANSPORT_DENIED: 5,
    Code.HANDSHAKE_INCOMPLETE: 5, Code.TLS_VERSION_LOW: 5,
    Code.VERIFY_MODE_UNSAFE: 5, Code.NO_PEER_CERT: 5, Code.CERT_MALFORMED: 5,
    Code.CERT_EXPIRED: 5, Code.CERT_NOT_YET_VALID: 5, Code.CERT_AMBIGUOUS: 5,
    Code.SAN_MISSING: 5, Code.SAN_INVALID: 5, Code.SPKI_MISMATCH: 5,
    Code.UNKNOWN_AGENT: 5, Code.UNKNOWN_CA: 5, Code.PEER_VANISHED: 5, Code.PEER_REPLACED: 5,
    Code.PEER_CREDS_CHANGED: 5, Code.PEER_EXE_UNREADABLE: 5,
    Code.PROC_UNREADABLE: 5, Code.NO_PEERCRED: 5, Code.PIDFD_UNAVAILABLE: 5,
    Code.POP_REQUIRED: 6, Code.POP_MALFORMED: 6, Code.POP_UNKNOWN_KEY: 6,
    Code.POP_MISMATCH: 6, Code.POP_BAD_SIGNATURE: 6, Code.POP_STALE: 6,
    Code.POP_BINDING: 6, Code.POP_REPLAY: 6,
    Code.CB_UNAVAILABLE: 6, Code.CB_MISMATCH: 6,
    Code.REVOKED: 7, Code.REPLAY: 7, Code.BUDGET_EXHAUSTED: 7,
    Code.BUDGET_CAP_CHANGED: 7, Code.STATE_UNAVAILABLE: 7,
    Code.EVIDENCE_BROKEN: 7,
    Code.POLICY_DENIED: 8, Code.SCOPE_MISMATCH: 8, Code.WRONG_AUDIENCE: 8,
    Code.WRONG_SESSION: 8, Code.WRONG_TASK: 8, Code.PEER_HOLDER_MISMATCH: 8,
    Code.TRUSTSET_EXPIRED: 8,
    Code.FRAME_MALFORMED: 9, Code.FRAME_TOO_LARGE: 9, Code.CONN_DEADLINE: 9,
    Code.SESSION_REQUIRED: 10, Code.SESSION_INVALID: 10,
    Code.SESSION_EXPIRED: 10, Code.SESSION_PARENT_BAD: 10,
    Code.SESSION_REVOKED: 10,
}

_RETRYABLE: frozenset[Code] = frozenset({
    Code.SIGNER_UNAVAILABLE,
    Code.SOURCE_UNAVAILABLE, Code.SOURCE_TIMEOUT,
    Code.PIN_STORE_UNAVAIL, Code.PIN_CONFLICT,
    Code.STATE_UNAVAILABLE, Code.CONN_DEADLINE,
})

assert set(_CODE_LAYER) == set(Code), "every Code must have a layer"
assert _RETRYABLE <= set(Code)


class Reject(Exception):
    """The only exception every layer raises (R3).

    `code` is a member of `Code`.  `detail` is free-form, at most
    MAX_REJECT_DETAIL characters, printable-ASCII (control characters
    are replaced with '?'), and must never contain key material,
    signatures, nonces, or unescaped attacker-controlled bytes — it
    will end up in logs.

    `retryable` is derived from `code` by default.  A raise site that
    has context the code cannot express (e.g. SOURCE_TIMEOUT on the
    final retry of a batch) MAY override it explicitly; callers may
    use `retryable` to decide backoff, never to decide trust.
    """

    def __init__(
        self,
        code: Code,
        detail: str = "",
        *,
        retryable: Optional[bool] = None,
        context: Optional[Mapping[str, str]] = None,
        cause: Optional[BaseException] = None,
    ) -> None:
        super().__init__(f"{code.value}: {detail}" if detail else code.value)
        self.code = code
        self.detail = ascii_safe(detail)
        self.retryable = code.retryable if retryable is None else retryable
        self.context: Mapping[str, str] = dict(context or {})
        if cause is not None:
            self.__cause__ = cause
