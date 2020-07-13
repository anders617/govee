#!/bin/bash

until ./build/apps/govee > log.out 2> log.out; do
    echo "Server 'govee' crashed with exit code $?.  Respawning.." >&2
    sleep 1
done