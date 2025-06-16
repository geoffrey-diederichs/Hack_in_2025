#!/bin/bash

rm -f /flag* /app/flag*
[[ -z "$FLAG_FILE" ]] && export FLAG_FILE="/app/flag.txt"
[[ -z "$FLAG" ]] && (echo "Flag not specified!" && exit 1)
echo $FLAG > "$FLAG_FILE"
rm -- "$0"
/docker-entrypoint.sh