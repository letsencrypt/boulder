#!/usr/bin/env bash

# Lists all .proto files in the same directory as the //go:generate
# command which is calling this script.
PROTO_FILES=$(ls "${PWD}"/*.proto)
# Should point to /path/to/boulder, given that this script
# lives in the //grpc subdirectory of the boulder repo.
ROOT_DIR=$(dirname $(dirname $(readlink -f "$0")))

# -I "${PWD}" ensures that the imports search the current directory first
# -I "${ROOT_DIR}" ensures that our proto files can import each other
# --go_out="${PWD}" writes the .pb.go file adjacent to the generate.go file
# --go-grpc_out="${PWD}" does the same for _grpc.pb.go
# --go_opt=paths=source_relative derives output filenames from input filenames
# --go-grpc_opt=paths=source_relative does the same for _grpc.pb.go
# "${PROTO_FILES}" tells protoc to process all .proto files in the directory 
protoc -I "${PWD}" -I "${ROOT_DIR}" --go_out="${PWD}" --go-grpc_out="${PWD}" --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative "${PROTO_FILES}"
