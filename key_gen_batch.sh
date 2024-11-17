#!/bin/bash

for i in $(seq 1 10); do
    prefix=$(printf "ss%02d" $i)
    cargo run --bin keygen -- --outfile-prefix "$prefix"
done

