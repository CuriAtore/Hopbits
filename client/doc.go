// Package client is the open-source Hopbits node client: the wire protocol,
// the module contract every measurement kind implements, the safety layer
// that bounds what any node can be made to send, and the agent runtime.
//
// Regenerate the protocol code after editing anything under proto/:
//
//	go generate github.com/hopbits/client
package client

//go:generate go run github.com/bufbuild/buf/cmd/buf@v1.75.0 lint
//go:generate go run github.com/bufbuild/buf/cmd/buf@v1.75.0 generate
