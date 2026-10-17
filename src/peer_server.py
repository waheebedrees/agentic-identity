import json
import os
import socket
import ssl
import time
from contracts import Code, Reject
from shared import material, peer_identity, channel_binding

SOCKET_PATH = os.environ["SPIFFE_ENDPOINT_SOCKET"]
PORT = int(os.environ["LISTEN_PORT"])
SELF = os.environ["AGENT_ID"]
HANDSHAKE_S = float(os.environ.get("HANDSHAKE_TIMEOUT", "10"))
PEERS = {p["id"]: p for p in json.loads(os.environ["PEERS"])}
CTX, OWN, DIGEST = material(SOCKET_PATH, now=int(time.time()), server_side=True)


def handle(conn) -> None:
    conn.settimeout(HANDSHAKE_S)                    
    tls = None
    try:
        ctx, own, digest = CTX, OWN, DIGEST

        if own.agent_id != SELF:                     
            raise Reject(Code.PEER_HOLDER_MISMATCH, own.agent_id)


        tls = ctx.wrap_socket(conn, server_side=True)
        now = int(time.time())
        peer = peer_identity(tls, trust_domain=own.trust_domain, now=now)
        if peer.agent_id not in PEERS:            
            print(f"reject: {peer.agent_id}", flush=True)
            return

        print(f"peer: {peer.agent_id}")
        print(f"credential: {peer.credential_id}")
        print(f"bundle: {digest}")
        print(f"binding_len: {len(channel_binding(tls))}")
        tls.sendall(b"hello from peer\n")

    except Reject as e:
        print(f"reject {e.code.value}: {e.detail}", flush=True)  

    except (OSError, ssl.SSLError) as e:
        print(f"transport error: {type(e).__name__}: {e}", flush=True)
        if isinstance(e, ssl.SSLError):
            print(
                f"  verify_message: {getattr(e, 'verify_message', None)}", flush=True)
            print(f"  library: {getattr(e, 'library', None)}", flush=True)
            print(f"  reason:  {getattr(e, 'reason', None)}", flush=True)
            print(f"  errno:   {getattr(e, 'errno', None)}", flush=True)
            
    finally:                                         
        if tls is not None:
            tls.close()
        conn.close()


def run_server() -> None:
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", PORT))
        s.listen(16)
        print(f"listening on :{PORT}", flush=True)
        while True:
            conn, _addr = s.accept()
            handle(conn)          


if __name__ == "__main__":
    run_server()
