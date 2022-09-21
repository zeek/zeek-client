"""This module provides compatibility goop for OpenSSL."""
import os.path
import ssl

from .config import CONFIG

def get_context():  # pragma: no cover
    """Returns an ssl.SSLContext for TLS-protected websocket communication.

    This is a helper for communication protected with SSL, with or without
    authentication. This mirrors Broker's default mode of operation:
    SSL-protected, but without validation/authentication.

    This may raise ssl.SSLError for SSL problems, and OSError if any cert/key
    files cannot be loaded.

    authenticate: if False (default), configures the context to disable
        validation and permit unathenticated ciphersuites.

    Returns: ssl.SSLContext.
    """
    # Newer OpenSSL versions prefer PROTOCOL_TLS_CLIENT over PROTOCOL_TLS, so
    # see if the former is available.
    if hasattr(ssl, 'PROTOCOL_TLS_CLIENT'):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)

    ssl_certificate = CONFIG.get('ssl', 'certificate') or None
    ssl_keyfile = CONFIG.get('ssl', 'keyfile') or None
    ssl_cafile = CONFIG.get('ssl', 'cafile') or None
    ssl_capath = CONFIG.get('ssl', 'capath') or None
    ssl_passphrase = CONFIG.get('ssl', 'passphrase') or None

    if ssl_certificate and not os.path.isfile(ssl_certificate):
        raise FileNotFoundError('SSL certificate file "{}" not found'
                                .format(ssl_certificate))
    if ssl_keyfile and not os.path.isfile(ssl_keyfile):
        raise FileNotFoundError('SSL private key file "{}" not found'
                                .format(ssl_keyfile))
    if ssl_cafile and not os.path.isfile(ssl_cafile):
        raise FileNotFoundError('SSL trusted CAs file "{}" not found'
                                .format(ssl_cafile))
    if ssl_capath and not os.path.isdir(ssl_capath):
        raise FileNotFoundError('SSL trusted CAs path "{}" not found'
                                .format(ssl_capath))

    if not ssl_certificate:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # This mirrors the selection in Broker, and depends on the OpenSSL version:
        try:
            ctx.set_ciphers('AECDH-AES256-SHA@SECLEVEL=0')
        except ssl.SSLError:
            ctx.set_ciphers('AECDH-AES256-SHA')
    else:
        # This too mirrors Broker:
        ctx.set_ciphers('HIGH:!aNULL:!MD5')
        ctx.load_cert_chain(ssl_certificate, ssl_keyfile, ssl_passphrase)
        if ssl_cafile or ssl_capath:
            ctx.load_verify_locations(cafile=ssl_cafile, capath=ssl_capath)

    return ctx

def get_websocket_sslopt():
    """Returns a TLS options dict for websocket-client.

    The resulting dict is suitable for the websocket.WebSocket()
    constructor. It's required for older websocket-client versions that don't
    yet support passing an SSL context explicitly. This can go when everyone can
    easily use websocket-client >= 1.2.2.
    """
    ssl_certificate = CONFIG.get('ssl', 'certificate') or None
    ssl_keyfile = CONFIG.get('ssl', 'keyfile') or None
    ssl_cafile = CONFIG.get('ssl', 'cafile') or None
    ssl_capath = CONFIG.get('ssl', 'capath') or None
    ssl_passphrase = CONFIG.get('ssl', 'passphrase') or None

    if ssl_certificate and not os.path.isfile(ssl_certificate):
        raise FileNotFoundError('SSL certificate file "{}" not found'
                                .format(ssl_certificate))
    if ssl_keyfile and not os.path.isfile(ssl_keyfile):
        raise FileNotFoundError('SSL private key file "{}" not found'
                                .format(ssl_keyfile))
    if ssl_cafile and not os.path.isfile(ssl_cafile):
        raise FileNotFoundError('SSL trusted CAs file "{}" not found'
                                .format(ssl_cafile))
    if ssl_capath and not os.path.isdir(ssl_capath):
        raise FileNotFoundError('SSL trusted CAs path "{}" not found'
                                .format(ssl_capath))

    # SSL options as understood by websocket-client
    sslopt = {}

    if not ssl_certificate:
        sslopt['cert_reqs'] = ssl.CERT_NONE
        if ssl.OPENSSL_VERSION_NUMBER >= 0x10100000:
            sslopt['ciphers'] = 'AECDH-AES256-SHA@SECLEVEL=0'
        else:
            sslopt['ciphers'] = 'AECDH-AES256-SHA'
    else:
        sslopt['ciphers'] = 'HIGH:!aNULL:!MD5'

        if ssl_certificate:
            sslopt['certfile'] = ssl_certificate
        if ssl_keyfile:
            sslopt['keyfile'] = ssl_keyfile
        if ssl_passphrase:
            sslopt['password'] = ssl_passphrase
        if ssl_cafile:
            sslopt['ca_certs'] = ssl_cafile
        if ssl_capath:
            sslopt['ca_cert_path'] = ssl_capath

    return sslopt
