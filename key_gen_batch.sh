#!/bin/bash

for i in $(seq 21 50); do
    prefix=$(printf "gs%02d" $i)
    cargo run --bin keygen -- --outfile-prefix "$prefix"
done

