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

    :param folder: Full path to folder (Ex: C:\\users\\bob\\images\\). If last path separator is omitted, then the function
     adds it.
    :param base_filename: The base filename of the file (Ex: image.png).
    :return: The next available filename (Ex: image_2.png).

    """
    import os

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
