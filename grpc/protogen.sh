#!/usr/bin/env bash

# Points to the directory of the file whose //go:generate
# directive is calling this script.
PROTO_DIR=$(pwd)
# Lists all .proto files in the directory.
PROTO_FILES=$(ls $PROTO_DIR/*.proto)
# Should point to /path/to/boulder, given that this script
# lives in the //grpc subdirectory of the boulder repo.
ROOT_DIR=`dirname $(dirname $(readlink -f "$0"))`

# -I $PROTO_DIR ensures that the import path searches neighboring files first
# -I $ROOT_DIR ensures that our proto files can import each other
# --go_out=$PROTO_DIR writes the .pb.go file adjacent to the generate.go file
# --go-grpc_out=$PROTO_DIR writes the _grpc.pb.go file in the same place
# --go_opt=paths=source_relative derives output filenames from input filenames
# --go-grpc_opt=paths=source_relative does the same for _grpc.pb.go
# $PROTO_FILES tells protoc to process all .proto files in the directory 
protoc -I $PROTO_DIR -I $ROOT_DIR --go_out=$PROTO_DIR --go-grpc_out=$PROTO_DIR --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative $PROTO_FILES
