package rpc

// Client describes the functions an RPC Client performs
type Client interface {
	DispatchSync(string, []byte) ([]byte, error)
}

// Server describes the functions an RPC Server performs
type Server interface {
	Handle(string, messageHandler)
}
