

from __future__ import annotations

import hashlib
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from spiffe import WorkloadApiClient # type: ignore

from channel_binding import (
    RFC9266_CONTEXT,
    RFC9266_LABEL,
    RFC9266_LENGTH,
    ChannelBindingError,
    native_export_keying_material,
)
from contracts import Code, Reject, Timestamp

SPIFFE_URI_PREFIX = "spiffe://"
TLS_VERSIONS = ("TLSv1.3",)
MIN_SVID_TTL_S = 60
CONNECT_TIMEOUT_S = 5.0


def _normalize(path: str) -> str:
    if path.startswith("unix://"):
        return path
    if path.startswith("/"):
        return f"unix://{path}"
    raise ValueError(f"bad SPIFFE socket path: {path!r}")


@dataclass(frozen=True, slots=True)
class SpiffeIdentity:
    """Authenticated workload identity from an X.509-SVID.

    credential_id identifies THIS CERTIFICATE.  It is not a
    Capchain kid (which is sha256 over a raw Ed25519 session key).
    Never substitute one for the other.
    """

    agent_id: str                  # canonical SPIFFE ID
    trust_domain: str
    credential_id: str             # x509-sha256:<hex sha256 of leaf DER>
    bundle_digest: str             # sha256:<hex sha256 of bundle PEM>
    not_before: Timestamp
    expires_at: Timestamp


@dataclass(frozen=True, slots=True)
class AuthenticatedChannel:
    """A live TLS connection with an authenticated peer."""

    sslsock: Any
    local: SpiffeIdentity
    peer: SpiffeIdentity
    tls_version: str

    def channel_binding(self) -> bytes:
        """RFC 9266 exporter for THIS connection. Never cached."""
        return channel_binding(self.sslsock)



def _spiffe_uris(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        raise Reject(Code.SAN_MISSING, "certificate has no SAN") from None
    return tuple(
        u for u in san.get_values_for_type(x509.UniformResourceIdentifier)
        if u.startswith(SPIFFE_URI_PREFIX)
    )


def _trust_domain_of(spiffe_id: str) -> str:
    rest = spiffe_id[len(SPIFFE_URI_PREFIX):]
    td, _, path = rest.partition("/")
    if not td or not path:
        raise Reject(Code.SAN_INVALID,
                     f"non-canonical SPIFFE ID {spiffe_id!r}")
    return td


def _validity(cert: x509.Certificate) -> tuple[Timestamp, Timestamp]:
    try:
        nb = int(cert.not_valid_before_utc.timestamp())
        na = int(cert.not_valid_after_utc.timestamp())
    except AttributeError:
        nb = int(cert.not_valid_before.timestamp())
        na = int(cert.not_valid_after.timestamp())
    return nb, na


def _identity_from_leaf(
    leaf: x509.Certificate, *, trust_domain: str, now: Timestamp,
    bundle_digest: str,
) -> SpiffeIdentity:
    uris = _spiffe_uris(leaf)
    if not uris:
        raise Reject(Code.SAN_INVALID, "no spiffe:// URI SAN")
    if len(set(uris)) > 1:
        raise Reject(Code.CERT_AMBIGUOUS,
                     f"{len(set(uris))} distinct SPIFFE IDs")
    agent_id = uris[0]
    if _trust_domain_of(agent_id) != trust_domain:
        raise Reject(Code.UNKNOWN_AGENT, "SVID trust domain mismatch")
    nb, na = _validity(leaf)
    if now < nb:
        raise Reject(Code.CERT_NOT_YET_VALID, f"valid from {nb}")
    if now > na:
        raise Reject(Code.CERT_EXPIRED, f"expired at {na}")
    return SpiffeIdentity(
        agent_id=agent_id,
        trust_domain=trust_domain,
        credential_id="x509-sha256:"
        + hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest(),
        bundle_digest=bundle_digest,
        not_before=nb,
        expires_at=na,
    )


def _svid_expiry(svid: Any) -> Timestamp | None:
    raw = getattr(svid, "x509_svid_expiry", None)
    return int(raw) if isinstance(raw, int) else None


def _write_memfd(data: bytes) -> int:
    fd = os.memfd_create("spire", 0)
    os.write(fd, data)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def _load_key_and_chain(ctx: ssl.SSLContext, chain_pem: bytes, key_pem: bytes) -> None:
    fd = _write_memfd(chain_pem + key_pem)
    try:
        ctx.load_cert_chain(f"/proc/self/fd/{fd}")
    finally:
        os.close(fd)


def _load_bundle(ctx: ssl.SSLContext, bundle_pem: bytes) -> None:
    fd = _write_memfd(bundle_pem)
    try:
        ctx.load_verify_locations(f"/proc/self/fd/{fd}")
    finally:
        os.close(fd)


def material(
    socket_path: str | Path,
    *,
    now: Timestamp,
    server_side: bool = False,
    min_ttl_s: int = MIN_SVID_TTL_S,
) -> tuple[ssl.SSLContext, SpiffeIdentity, str]:
    """Fetch SVID + own trust-domain bundle; build an mTLS context.

    Fails closed: any Workload API or freshness problem raises
    Reject.  The private key never touches the filesystem.
    """
    with WorkloadApiClient(socket_path=_normalize(socket_path)) as c:
        svid = c.fetch_x509_svid()
        bundles = c.fetch_x509_bundles()

    if not svid.cert_chain:
        raise Reject(Code.NO_PEER_CERT, "agent returned no SVID chain")

    td = svid.spiffe_id.trust_domain
    bundle = bundles.get_bundle_for_trust_domain(td)
    if bundle is None or not bundle.x509_authorities:
        raise Reject(Code.ANCHOR_INCONSISTENT, f"no bundle for {td!r}")

    bundle_pem = b"".join(
        a.public_bytes(serialization.Encoding.PEM)
        for a in bundle.x509_authorities
    )
    bundle_digest = hashlib.sha256(bundle_pem).hexdigest()

    expiry = _svid_expiry(svid)
    if expiry is not None and expiry - now < min_ttl_s:
        raise Reject(Code.CERT_EXPIRED,
                     f"SVID ttl {expiry - now}s < {min_ttl_s}s")

    leaf = svid.cert_chain[0]
    own = _identity_from_leaf(
        leaf, trust_domain=td, now=now,
        bundle_digest="sha256:" + bundle_digest,
    )

    chain_pem = b"".join(
        c.public_bytes(serialization.Encoding.PEM) for c in svid.cert_chain
    )
    key = svid.private_key
    key_pem = key if isinstance(key, (bytes, bytearray)) else key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    ctx = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # SPIFFE ID is in URI SAN, not DNS
    _load_key_and_chain(ctx, chain_pem, key_pem)
    _load_bundle(ctx, bundle_pem)
    return ctx, own, "sha256:" + bundle_digest


def peer_identity(
    tls: ssl.SSLSocket, *, trust_domain: str, now: Timestamp
) -> SpiffeIdentity:
    """Authenticate the peer.  Precondition: chain already verified
    by the SSLContext against the SPIFFE bundle."""
    der = tls.getpeercert(binary_form=True)
    if not der:
        raise Reject(Code.NO_PEER_CERT, "peer sent no certificate")
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:
        raise Reject(Code.CERT_MALFORMED, type(e).__name__) from e
    return _identity_from_leaf(
        cert, trust_domain=trust_domain, now=now, bundle_digest=""
    )


def channel_binding(
    sslsock: ssl.SSLSocket,
    length: int = RFC9266_LENGTH,
    label: bytes | str = RFC9266_LABEL,
    context: bytes | str | None = RFC9266_CONTEXT,
) -> bytes:
    try:
        material = native_export_keying_material(
            sslsock, length=length, label=label, context=context
        )
    except (RuntimeError, ssl.SSLError, ValueError) as exc:
        raise ChannelBindingError(
            "NO_CHANNEL_BINDING",
            f"export_keying_material unavailable: {exc}",
        ) from None

    if not material:
        raise ChannelBindingError(
            "NO_CHANNEL_BINDING", "empty exporter output")
    return material
