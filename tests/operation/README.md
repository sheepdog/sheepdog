# Operation tests
This directory contains **operation tests**, for testing `SD_OP_*` operations.
Tests are written with PyUnit framework.

## To add tests
Edit or add `test_*.py`.

## To add operations
Edit `SheepdogClient` class in `sheep.py`.
If a new C struct is needed, add a corresponding Python class using Struct.

## To add fixtures
Edit `fixture.py`.

## How to start operation tests
$ sudo python test_*.py
e.g. $ sudo python test_3nodes_2copies.py
