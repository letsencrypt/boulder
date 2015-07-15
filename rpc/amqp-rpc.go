// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// TODO: AMQP-RPC messages should be wrapped in JWS.  To implement that,
// it will be necessary to make the following changes:
//
// * Constructors: Provision private key, acceptable public keys
// * After consume: Verify and discard JWS wrapper
// * Before publish: Add JWS wrapper

// General AMQP helpers

// XXX: I *think* these constants are appropriate.
// We will probably want to tweak these in the future.
const (
	AmqpExchange     = "boulder"
	AmqpExchangeType = "topic"
	AmqpInternal     = false
	AmqpDurable      = false
	AmqpDeleteUnused = false
	AmqpExclusive    = false
	AmqpNoWait       = false
	AmqpNoLocal      = false
	AmqpAutoAck      = true
	AmqpMandatory    = false
	AmqpImmediate    = false
)

// A simplified way to get a channel for a given AMQP server
func amqpConnect(url string) (ch *amqp.Channel, err error) {
	conn, err := amqp.Dial(url)
	if err != nil {
		return
	}

	ch, err = conn.Channel()
	return
}

// A simplified way to declare and subscribe to an AMQP queue
func amqpSubscribe(ch *amqp.Channel, name string, log *blog.AuditLogger) (msgs <-chan amqp.Delivery, err error) {
	err = ch.ExchangeDeclare(
		AmqpExchange,
		AmqpExchangeType,
		AmqpDurable,
		AmqpDeleteUnused,
		AmqpInternal,
		AmqpNoWait,
		nil)
	if err != nil {
		log.Crit(fmt.Sprintf("Could not declare exchange: %s", err))
		return
	}

	q, err := ch.QueueDeclare(
		name,
		AmqpDurable,
		AmqpDeleteUnused,
		AmqpExclusive,
		AmqpNoWait,
		nil)
	if err != nil {
		log.Crit(fmt.Sprintf("Could not declare queue: %s", err))
		return
	}

	err = ch.QueueBind(
		name,
		name,
		AmqpExchange,
		false,
		nil)
	if err != nil {
		log.Crit(fmt.Sprintf("Could not bind queue: %s", err))
		return
	}

	msgs, err = ch.Consume(
		q.Name,
		"",
		AmqpAutoAck,
		AmqpExclusive,
		AmqpNoLocal,
		AmqpNoWait,
		nil)
	if err != nil {
		log.Crit(fmt.Sprintf("Could not subscribe to queue: %s", err))
		return
	}

	return
}

// AmqpRPCServer listens on a specified queue within an AMQP channel.
// When messages arrive on that queue, it dispatches them based on type,
// and returns the response to the ReplyTo queue.
//
// To implement specific functionality, using code should use the Handle
// method to add specific actions.
type AmqpRPCServer struct {
	serverQueue   string
	channel       *amqp.Channel
	log           *blog.AuditLogger
	dispatchTable map[string]func([]byte) ([]byte, error)
}

// NewAmqpRPCServer creates a new RPC server on the given queue and channel.
// Note that you must call Start() to actually start the server
// listening for requests.
func NewAmqpRPCServer(serverQueue string, channel *amqp.Channel) *AmqpRPCServer {
	log := blog.GetAuditLogger()
	return &AmqpRPCServer{
		serverQueue:   serverQueue,
		channel:       channel,
		log:           log,
		dispatchTable: make(map[string]func([]byte) ([]byte, error)),
	}
}

// Handle registers a function to handle a particular method.
func (rpc *AmqpRPCServer) Handle(method string, handler func([]byte) ([]byte, error)) {
	rpc.dispatchTable[method] = handler
}

// RPCError is a JSON wrapper for error as it cannot be un/marshalled
// due to type interface{}.
type RPCError struct {
	Value string `json:"value"`
	Type  string `json:"type,omitempty"`
}

// Wraps a error in a RPCError so it can be marshalled to
// JSON.
func wrapError(err error) (rpcError RPCError) {
	if err != nil {
		rpcError.Value = err.Error()
		switch err.(type) {
		case core.InternalServerError:
			rpcError.Type = "InternalServerError"
		case core.NotSupportedError:
			rpcError.Type = "NotSupportedError"
		case core.MalformedRequestError:
			rpcError.Type = "MalformedRequestError"
		case core.UnauthorizedError:
			rpcError.Type = "UnauthorizedError"
		case core.NotFoundError:
			rpcError.Type = "NotFoundError"
		case core.SyntaxError:
			rpcError.Type = "SyntaxError"
		case core.SignatureValidationError:
			rpcError.Type = "SignatureValidationError"
		case core.CertificateIssuanceError:
			rpcError.Type = "CertificateIssuanceError"
		}
	}
	return
}

// Unwraps a RPCError and returns the correct error type.
func unwrapError(rpcError RPCError) (err error) {
	if rpcError.Value != "" {
		switch rpcError.Type {
		case "InternalServerError":
			err = core.InternalServerError(rpcError.Value)
		case "NotSupportedError":
			err = core.NotSupportedError(rpcError.Value)
		case "MalformedRequestError":
			err = core.MalformedRequestError(rpcError.Value)
		case "UnauthorizedError":
			err = core.UnauthorizedError(rpcError.Value)
		case "NotFoundError":
			err = core.NotFoundError(rpcError.Value)
		case "SyntaxError":
			err = core.SyntaxError(rpcError.Value)
		case "SignatureValidationError":
			err = core.SignatureValidationError(rpcError.Value)
		case "CertificateIssuanceError":
			err = core.CertificateIssuanceError(rpcError.Value)
		default:
			err = errors.New(rpcError.Value)
		}
	}
	return
}

// RPCResponse is a stuct for wire-representation of response messages
// used by DispatchSync
type RPCResponse struct {
	ReturnVal []byte   `json:"returnVal,omitempty"`
	Error     RPCError `json:"error,omitempty"`
}

// Start starts the AMQP-RPC server running in a separate thread.
// There is currently no Stop() method.
func (rpc *AmqpRPCServer) Start() (err error) {
	msgs, err := amqpSubscribe(rpc.channel, rpc.serverQueue, rpc.log)
	if err != nil {
		return
	}

	go func() {
		for msg := range msgs {
			// XXX-JWS: jws.Verify(body)
			cb, present := rpc.dispatchTable[msg.Type]
			rpc.log.Info(fmt.Sprintf(" [s<][%s][%s] received %s(%s) [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, core.B64enc(msg.Body), msg.CorrelationId))
			if !present {
				// AUDIT[ Misrouted Messages ] f523f21f-12d2-4c31-b2eb-ee4b7d96d60e
				rpc.log.Audit(fmt.Sprintf(" [s<][%s][%s] Misrouted message: %s - %s - %s", rpc.serverQueue, msg.ReplyTo, msg.Type, core.B64enc(msg.Body), msg.CorrelationId))
				continue
			}
			var response RPCResponse
			response.ReturnVal, err = cb(msg.Body)
			response.Error = wrapError(err)
			jsonResponse, err := json.Marshal(response)
			if err != nil {
				// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
				rpc.log.Audit(fmt.Sprintf(" [s>][%s][%s] Error condition marshalling RPC response %s [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, msg.CorrelationId))
				continue
			}
			rpc.log.Info(fmt.Sprintf(" [s>][%s][%s] replying %s(%s) [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, core.B64enc(jsonResponse), msg.CorrelationId))
			rpc.channel.Publish(
				AmqpExchange,
				msg.ReplyTo,
				AmqpMandatory,
				AmqpImmediate,
				amqp.Publishing{
					CorrelationId: msg.CorrelationId,
					Type:          msg.Type,
					Body:          jsonResponse, // XXX-JWS: jws.Sign(privKey, body)
				})
		}
	}()
	return
}

// AmqpRPCCLient is an AMQP-RPC client that sends requests to a specific server
// queue, and uses a dedicated response queue for responses.
//
// To implement specific functionality, using code uses the Dispatch()
// method to send a method name and body, and get back a response. So
// you end up with wrapper methods of the form:
//
// ```
//   request = /* serialize request to []byte */
//   response = <-AmqpRPCCLient.Dispatch(method, request)
//   return /* deserialized response */
// ```
//
// Callers that don't care about the response can just call Dispatch()
// and ignore the return value.
//
// DispatchSync will manage the channel for you, and also enforce a
// timeout on the transaction (default 60 seconds)
type AmqpRPCCLient struct {
	serverQueue string
	clientQueue string
	channel     *amqp.Channel
	timeout     time.Duration
	log         *blog.AuditLogger

	mu      sync.Mutex
	pending map[string]chan []byte
}

// NewAmqpRPCClient constructs an RPC client using AMQP
func NewAmqpRPCClient(clientQueuePrefix, serverQueue string, channel *amqp.Channel) (rpc *AmqpRPCCLient, err error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	clientQueue := fmt.Sprintf("%s.%s", clientQueuePrefix, hostname)

	rpc = &AmqpRPCCLient{
		serverQueue: serverQueue,
		clientQueue: clientQueue,
		channel:     channel,
		pending:     make(map[string]chan []byte),
		timeout:     10 * time.Second,
		log:         blog.GetAuditLogger(),
	}

	// Subscribe to the response queue and dispatch
	msgs, err := amqpSubscribe(rpc.channel, clientQueue, rpc.log)
	if err != nil {
		return nil, err
	}

	go func() {
		for msg := range msgs {
			// XXX-JWS: jws.Sign(privKey, body)
			corrID := msg.CorrelationId
			rpc.mu.Lock()
			responseChan, present := rpc.pending[corrID]
			rpc.mu.Unlock()

			rpc.log.Debug(fmt.Sprintf(" [c<][%s] response %s(%s) [%s]", clientQueue, msg.Type, core.B64enc(msg.Body), corrID))
			if !present {
				// AUDIT[ Misrouted Messages ] f523f21f-12d2-4c31-b2eb-ee4b7d96d60e
				rpc.log.Audit(fmt.Sprintf(" [c<][%s] Misrouted message: %s - %s - %s", clientQueue, msg.Type, core.B64enc(msg.Body), msg.CorrelationId))
				continue
			}
			responseChan <- msg.Body
			rpc.mu.Lock()
			delete(rpc.pending, corrID)
			rpc.mu.Unlock()
		}
	}()

	return rpc, err
}

// SetTimeout configures the maximum time DispatchSync will wait for a response
// before returning an error.
func (rpc *AmqpRPCCLient) SetTimeout(ttl time.Duration) {
	rpc.timeout = ttl
}

// Dispatch sends a body to the destination, and returns a response channel
// that can be used to monitor for responses, or discarded for one-shot
// actions.
func (rpc *AmqpRPCCLient) Dispatch(method string, body []byte) chan []byte {
	// Create a channel on which to direct the response
	// At least in some cases, it's important that this channel
	// be buffered to avoid deadlock
	responseChan := make(chan []byte, 1)
	corrID := core.NewToken()
	rpc.mu.Lock()
	rpc.pending[corrID] = responseChan
	rpc.mu.Unlock()

	// Send the request
	rpc.log.Debug(fmt.Sprintf(" [c>][%s] requesting %s(%s) [%s]", rpc.clientQueue, method, core.B64enc(body), corrID))
	rpc.channel.Publish(
		AmqpExchange,
		rpc.serverQueue,
		AmqpMandatory,
		AmqpImmediate,
		amqp.Publishing{
			CorrelationId: corrID,
			ReplyTo:       rpc.clientQueue,
			Type:          method,
			Body:          body, // XXX-JWS: jws.Sign(privKey, body)
		})

	return responseChan
}

// DispatchSync sends a body to the destination, and blocks waiting on a response.
func (rpc *AmqpRPCCLient) DispatchSync(method string, body []byte) (response []byte, err error) {
	select {
	case jsonResponse := <-rpc.Dispatch(method, body):
		var rpcResponse RPCResponse
		err = json.Unmarshal(jsonResponse, &rpcResponse)
		if err != nil {
			return
		}
		err = unwrapError(rpcResponse.Error)
		if err != nil {
			return
		}
		response = rpcResponse.ReturnVal
		return
	case <-time.After(rpc.timeout):
		rpc.log.Warning(fmt.Sprintf(" [c!][%s] AMQP-RPC timeout [%s]", rpc.clientQueue, method))
		err = errors.New("AMQP-RPC timeout")
		return
	}
}
