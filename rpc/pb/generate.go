package va

//go:generate protoc --go_out=plugins=grpc:. core/core.proto
//go:generate protoc --go_out=plugins=grpc,Mcore/core.proto=github.com/letsencrypt/boulder/rpc/pb/core:. va/va.proto
