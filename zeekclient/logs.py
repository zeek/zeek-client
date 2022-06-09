"""Logging configuration for zeek-client."""
import logging

LOG = logging.getLogger(__name__)
LOG.addHandler(logging.NullHandler())


def configure(verbosity=0, rich_logging=False, stream=None):
    """Configures logging.

    Args:
        verbosity (int): the log level. Values 0-3 increase logging, larger
            values make no difference.

        rich_logging (bool): whether to use timestamped, log-style log formatting.
    """
    # Make log levels lower-case, looks better in informal logging
    for level in (logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG):
        logging.addLevelName(level, logging.getLevelName(level).lower())

    if rich_logging:
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)-8s %(message)s', '%Y-%m-%d %H:%M:%S')
    else:
        formatter = logging.Formatter('%(levelname)s: %(message)s')

    handler = logging.StreamHandler(stream=stream)
    handler.setFormatter(formatter)

    LOG.setLevel(logging.ERROR)

    if verbosity == 1:
        LOG.setLevel(logging.WARNING)
    elif verbosity == 2:
        LOG.setLevel(logging.INFO)
    elif verbosity >= 3:
        LOG.setLevel(logging.DEBUG)

    LOG.addHandler(handler)
