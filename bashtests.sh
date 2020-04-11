#!/bin/bash

tests=("basic.txt")

# putting in double quotes expands each var to sep word
for f in "${tests[@]}"; do
    # read the file line by line
    while IFS= read -r -u $f test_case; do
        echo $test_case
    done
done
