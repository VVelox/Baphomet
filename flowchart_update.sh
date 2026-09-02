#!/bin/sh
#
# Renders every graphviz source under docs/ ... each .dot becomes the .svg
# the markdown references, and a .png besides.

set -e

docs_dir="$(dirname "$0")/docs"

for dot_file in "$docs_dir"/*.dot; do
	[ -e "$dot_file" ] || continue
	base="${dot_file%.dot}"
	dot -Tsvg "$dot_file" -o "$base.svg"
	dot -Tpng "$dot_file" -o "$base.png"
	echo "rendered $base.svg and $base.png"
done
