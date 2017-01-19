from setuptools import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup_params = dict(
    name='analyzr',
    version='0.1.0',
    packages=['analyzr'],
    entry_points={
        'console_scripts': [
            'analyzr = analyzr.__main__:main',
        ],
    },
    author='Raphaël Doré & Raphaël Fournier',
    author_email='rdore@neomailbox.ch',
    description='Discover hosts on the network and draw its topology.',
    install_requires=requirements
)


def main():
    setup(**setup_params)


if '__main__' == __name__:
    main()
