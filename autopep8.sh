#!/usr/bin/env bash
# jue dic  3 01:49:53 CET 2015
# root@libcrack.so
set -e
path="."
test -z "$1" || path="$1"
for file in ${path}/*.py; do
    echo "(pep8) >> $file"
    autopep8 --in-place --aggressive --aggressive "${file}"
done
exit $?
