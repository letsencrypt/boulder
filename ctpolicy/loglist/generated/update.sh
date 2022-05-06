#!/bin/sh

# Always operate on files adjacent to this script, regardless of where it is
# called from.
this_dir=$(dirname $(readlink -f "$0"))

rm -f ${this_dir}/log_list_schema.json
curl https://www.gstatic.com/ct/log_list/v3/log_list_schema.json > ${this_dir}/log_list_schema.json

go install github.com/atombender/go-jsonschema/cmd/gojsonschema@latest
rm -f ${this_dir}/schema.go
gojsonschema -p generated ${this_dir}/log_list_schema.json > ${this_dir}/schema.go

rm -f ${this_dir}/log_list.json
curl https://www.gstatic.com/ct/log_list/v3/log_list.json > ${this_dir}/log_list.json
