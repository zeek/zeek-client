import uuid

def make_uuid(prefix=''):
    """Returns a prefixable  UUID string.

    The client uses this for event request/response identifiers.

    Args:
        prefix (string): prefix string to prepend to the UUID.
    """
    return prefix + str(uuid.uuid1())
