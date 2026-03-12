def generate_cbom(asset, tls=None, cert=None):

    tls = tls or {}
    cert = cert or {}

    return {
        "asset": asset,
        "tls_version": tls.get("tls_version"),
        "cipher_suite": tls.get("cipher_suite"),
        "key_exchange": tls.get("key_exchange"),
        "certificate_issuer": cert.get("issuer"),
        "certificate_subject": cert.get("subject"),
        "signature_algorithm": cert.get("signature_algorithm"),
        "key_size": cert.get("key_size"),
        "expiry": cert.get("expiry")
    }