#! /bin/sh
DIR=$(dirname $0)
PYTHONPATH=$DIR exec python -m scripts.analyzrctl $*
