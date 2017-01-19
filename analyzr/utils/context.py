from contextlib import contextmanager


@contextmanager
def redirect_stderr(new_target):
    """
    A context manager to temporarily redirect stderr that works with python < 3.5.
    Example use:

    :Example:
        ``with open(os.devnull, 'w') as f:``
            ``with redirect_stderr(f):``
                ``# stderr redirected to os.devnull. No annoying import messages printed on module import``
                ``from scapy.all import *``
        ``# stderr restored``

    Taken from http://stackoverflow.com/a/30733079
    """
    import sys
    old_target, sys.stderr = sys.stderr, new_target  # replace sys.stdout
    try:
        yield new_target  # run some code with the replaced stdout
    finally:
        sys.stderr = old_target  # restore to the previous value
