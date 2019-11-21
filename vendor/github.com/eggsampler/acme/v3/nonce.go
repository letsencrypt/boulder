package acme

import (
	"sync"
)

// Simple thread-safe stack impl
type nonceStack struct {
	lock  sync.Mutex
	stack []string
}

// Pushes a nonce to the stack.
// Doesn't push empty nonces, or if there's more than 100 nonces on the stack
func (ns *nonceStack) push(v string) {
	if v == "" {
		return
	}

	ns.lock.Lock()
	defer ns.lock.Unlock()

	if len(ns.stack) > 100 {
		return
	}

	ns.stack = append(ns.stack, v)
}

// Pops a nonce from the stack.
// Returns empty string if there are no nonces
func (ns *nonceStack) pop() string {
	ns.lock.Lock()
	defer ns.lock.Unlock()

	n := len(ns.stack)
	if n == 0 {
		return ""
	}

	v := ns.stack[n-1]
	ns.stack = ns.stack[:n-1]

	return v
}
