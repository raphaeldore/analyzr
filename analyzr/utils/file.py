from contextlib import contextmanager


@contextmanager
def open_with_error(filename: str, mode: str = "r", encoding: str = "utf-8"):
    try:
        f = open(filename, mode = mode, encoding=encoding)
    except IOError as err:
        yield None, err
    else:
        try:
            yield f, None
        finally:
            f.close()