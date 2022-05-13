#!/bin/sh

# Use the absolute path of this file to compute the path to the generated files.
repo_root=$(dirname $(dirname $(readlink -f "$0")))
gen_dir=${repo_root}/ctpolicy/loglist/generated

rm -f ${gen_dir}/log_list_schema.json
curl https://www.gstatic.com/ct/log_list/v3/log_list_schema.json > ${gen_dir}/log_list_schema.json

go install github.com/atombender/go-jsonschema/cmd/gojsonschema@latest
rm -f ${gen_dir}/schema.go
gojsonschema -p generated ${gen_dir}/log_list_schema.json > ${gen_dir}/schema.go

rm -f ${gen_dir}/log_list.json
curl https://www.gstatic.com/ct/log_list/v3/log_list.json > ${gen_dir}/log_list.json
