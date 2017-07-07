#!/bin/bash
# outputs directly markdown wiki content

DIR="$1"

echo -e "functions:\n"

FILES="$(find "$DIR" -name '*.lua' -print)"
for f in $FILES; do
    grep "^function" "$f" | sed -e 's,function *,,' -e 's,\(\)$,,g' -e 's,^,  \* ,g'
done
