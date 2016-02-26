import types
from io import StringIO
from os import path as op
from os.path import join
#from setuptools import setup
from cx_Freeze import setup, Executable


def _read(filename):
    with open(join(op.dirname(__file__), filename)) as fd:
        return fd.read()


def _read_reqs(filename):
    is_valid = (lambda _: _
                          and not any(_.startswith(ch) for ch in ['#', '-']))

    data = getattr(types, 'UnicodeType', str)(_read(filename))
    return list((_.strip() for _ in StringIO(data) if is_valid(_.strip())))


setup_params = dict(
    name='analyzr',
    version='1.0',
    packages=['analyzr', 'analyzr/utils', 'analyzr/core', 'analyzr/fingerprints', 'analyzr/networkdiscovery'],
    entry_points={
        'console_scripts': [
            'analyzr = analyzr:main',
        ],
    },
    include_package_data=True,
    url='https://raphaeldore.github.io/analyzr/',
    license='MIT',
    author='Raphaël Doré & Raphaël Fournier',
    author_email='rdore@neomailbox.ch',
    description='Scannez votre réseau pour découvrir sa topologie!',
    install_requires=_read_reqs('requirements.txt')
)


def main():
    setup(**setup_params)


if '__main__' == __name__:
    main()
