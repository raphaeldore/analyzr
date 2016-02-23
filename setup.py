import types
from os import path as op
from os.path import join
from cx_Freeze import setup, Executable

from io import StringIO


def _read(filename):
    with open(join(op.dirname(__file__), filename)) as fd:
        return fd.read()


def _read_reqs(filename):
    is_valid = (lambda _: _
                          and not any(_.startswith(ch) for ch in ['#', '-']))

    data = getattr(types, 'UnicodeType', str)(_read(filename))
    return list((_.strip() for _ in StringIO(data) if is_valid(_.strip())))


executables = [
    Executable("run.py")
]

setup_params = dict(
    name='analyzr',
    version='1.0',
    packages=['', 'core', 'utils', 'graphics', 'topology', 'fingerprints', 'networkdiscovery'],
    package_dir={'': 'analyzr'},
    url='https://raphaeldore.github.io/analyzr/',
    license='MIT',
    author='Raphaël Doré & Raphaël Fournier',
    author_email='rdore@neomailbox.ch',
    description='Scannez votre réseau pour découvrir sa topologie!',
    install_requires=_read_reqs('requirements.txt'),
    executables=executables

)


def main():
    setup(**setup_params)


if '__main__' == __name__:
    main()
