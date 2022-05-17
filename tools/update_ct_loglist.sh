#!/bin/sh

# This script updates the log list schema and log list files located at
# //ctpolicy/loglist/generated/. It downloads the Chrome CT Log List Version 3
# JSON schema and the corresponding JSON data file directly from where Google
# hosts them. It then runs the schema file through a JSON-schema-to-Go-struct
# autogeneration utility, to produce a set of Go structs which can unmarshal the
# log list file itself.

# This script expects github.com/atombender/go-jsonschema to be installed. This
# utility is included in the boulder-tools docker image. In order to ensure we
# all use the same version of this tool, please only run this script from inside
# our docker setup:
# $ docker-compose run boulder ./tools/update_ct_loglist.sh

set -e

# Use the absolute path of this file to compute the path to the generated files.
repo_root=$(dirname $(dirname $(readlink -f "$0")))
gen_dir=${repo_root}/ctpolicy/loglist/generated

curl https://www.gstatic.com/ct/log_list/v3/log_list_schema.json >| ${gen_dir}/log_list_schema.json

gojsonschema -p generated ${gen_dir}/log_list_schema.json >| ${gen_dir}/schema.go

curl https://www.gstatic.com/ct/log_list/v3/all_logs_list.json >| ${gen_dir}/log_list.json
