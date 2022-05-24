#!/bin/sh

# This script updates the log list JSON Schema and the Go structs generated
# from that schema.

# It is not intended to be run on a regular basis; we do not expect the JSON
# Schema to change. It is retained here for historical purposes, so that if/when
# the schema does change, or the ecosystem moves to a v4 version of the schema,
# regenerating these files will be quick and easy.

# This script expects github.com/atombender/go-jsonschema to be installed:
# $ go install github.com/atombender/go-jsonschema/cmd/gojsonschema@latest

set -e

this_dir=$(dirname $(readlink -f "$0"))

curl https://www.gstatic.com/ct/log_list/v3/log_list_schema.json >| ${this_dir}/log_list_schema.json

gojsonschema -p schema ${gen_dir}/log_list_schema.json >| ${this_dir}/schema.go
