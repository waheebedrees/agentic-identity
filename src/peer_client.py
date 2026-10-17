import json
import os
import socket
import ssl
import time
from shared import material, peer_identity, channel_binding
from contracts import Code, Reject

SOCKET_PATH = os.environ["SPIFFE_ENDPOINT_SOCKET"]
SELF = os.environ["AGENT_ID"]
PEERS = {p["id"]: p for p in json.loads(os.environ["PEERS"])}

# Which peer to call. If PEER_ID is set, use it; otherwise assume one peer.
TARGET_ID = os.environ.get("PEER_ID") or next(iter(PEERS))
PEER = PEERS[TARGET_ID]
HOST = PEER["host"]
PORT = int(PEER["port"])
CTX, OWN, DIGEST = material(SOCKET_PATH, now=int(time.time()))


def call() -> None:
    now = int(time.time())
    ctx, own, digest = CTX, OWN, DIGEST
    if own.agent_id != SELF:
        raise Reject(Code.PEER_HOLDER_MISMATCH,
                     f"workload holds {own.agent_id}, expected {SELF}")

    try:
        print(f"dialing {HOST}:{PORT} as {SELF}")
        with socket.create_connection((HOST, PORT), timeout=5) as raw:
            with ctx.wrap_socket(raw) as tls:
                peer = peer_identity(tls, trust_domain=own.trust_domain, now=now)

                if peer.agent_id not in PEERS:
                    raise Reject(Code.PEER_HOLDER_MISMATCH, peer.agent_id)

                binding = channel_binding(tls)
                print(f"peer: {peer.agent_id}")
                print(f"credential: {peer.credential_id}")
                print(f"bundle: {digest}")
                print("server says:", tls.recv(1024).decode().strip())


    except ssl.SSLError as e:
        print(f"SSL error: {e}", flush=True)
        print(
            f"  verify_message: {getattr(e, 'verify_message', None)}", flush=True)
        print(f"  library: {getattr(e, 'library', None)}", flush=True)
        print(f"  reason:  {getattr(e, 'reason', None)}", flush=True)
        raise

if __name__ == "__main__":
    call()
