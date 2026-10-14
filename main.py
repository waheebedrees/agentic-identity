import logging
import os
from pathlib import Path

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("agent")

SVID_DIR = Path(os.environ.get("SVID_CONTAINER_DIR", "/svid"))


def main() -> None:
    log.info("reading SVID from %s", SVID_DIR)

    cert = (SVID_DIR / "svid.0.pem").read_text()
    key = (SVID_DIR / "svid.0.key").read_text()
    bundle = (SVID_DIR / "bundle.0.pem").read_text()

    log.info("certificate loaded, %d bytes", len(cert))
    log.info("private key loaded, %d bytes", len(key))
    log.info("bundle loaded, %d bytes", len(bundle))

    # Extract SPIFFE ID from the cert
    import ssl
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    cert_obj = x509.load_pem_x509_certificate(cert.encode(), default_backend())
    for ext in cert_obj.extensions:
        if ext.oid.dotted_string == "2.5.29.17":  # subjectAltName
            for name in ext.value:
                if isinstance(name, x509.UniformResourceIdentifier):
                    log.info("SPIFFE ID: %s", name.value)


if __name__ == "__main__":
    main()
