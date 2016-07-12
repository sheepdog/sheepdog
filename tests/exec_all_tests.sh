#!/bin/bash
./functional/check
sudo python ./operation/test_3nodes_2copies.py
cd ./unit
make check
