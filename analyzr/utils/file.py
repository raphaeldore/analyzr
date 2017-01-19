import errno
import os
import sys
from contextlib import contextmanager


@contextmanager
def open_with_error(filename: str, mode: str = "r", encoding: str = "utf-8"):
    try:
        f = open(filename, mode=mode, encoding=encoding)
    except IOError as err:
        yield None, err
    else:
        try:
            yield f, None
        finally:
            f.close()


def get_next_file_path(folder: str, base_filename: str):
    """
    Python version of this C# code: http://stackoverflow.com/a/1078898

    Given a base file name, creates a unique filename. Check to see if the given file exists, and if it does
    tries to find the next available file name by appending numbers to the base filename until a valid filename is
    found.

    :param folder: Full path to folder. If last path separator is omitted, then the function adds it. Ex:

        ``C:\\users\\bob\\images\\``

        ``C:\\users\\bob\\images`` (will add the backslash)

    :param base_filename: The base filename of the file. Ex:

        ``image.png``

    :return: The next available filename (Ex: image_2.png).

    """
    pattern = "{filename}_{nb}{ext}"

    if not folder.endswith(os.path.sep):
        folder += os.path.sep

    full_path = folder + base_filename

    if not os.path.isfile(full_path):
        return full_path

    filename, file_extension = os.path.splitext(base_filename)

    min_nbr, max_nbr = 1, 2
    while os.path.isfile(
            os.path.join(folder, pattern.format(filename=filename, nb=str(max_nbr), ext=file_extension))):
        min_nbr = max_nbr
        max_nbr *= 2

    while max_nbr != min_nbr + 1:
        pivot = int((max_nbr + min_nbr) / 2)
        if os.path.isfile(
                os.path.join(folder, pattern.format(filename=filename, nb=str(pivot), ext=file_extension))):
            min_nbr = pivot
        else:
            max_nbr = pivot

    return os.path.join(folder, pattern.format(filename=filename, nb=str(max_nbr), ext=file_extension))


def make_sure_path_exists(path: str) -> None:
    """
    Makes sure that the path exists. If it does not exist
    creates the path (all directories and sub-directories in the given path).
    """
    if sys.version_info[:3] >= (3, 4, 1):
        os.makedirs(path, exist_ok=True)
    else:
        try:
            os.makedirs(path)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise
