// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package anvil

import (
	"errors"
	"github.com/streadway/amqp"
	"log"
	"time"
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
	AmqpExchange     = ""
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
func amqpSubscribe(ch *amqp.Channel, name string) (msgs <-chan amqp.Delivery, err error) {
	q, err := ch.QueueDeclare(
		name,
		AmqpDurable,
		AmqpDeleteUnused,
		AmqpExclusive,
		AmqpNoWait,
		nil)
	if err != nil {
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
	return
}

// An AMQP-RPC Server listens on a specified queue within an AMQP channel.
// When messages arrive on that queue, it dispatches them based on type,
// and returns the response to the ReplyTo queue.
//
// To implement specific functionality, using code should use the Handle
// method to add specific actions.
type AmqpRpcServer struct {
	serverQueue   string
	channel       *amqp.Channel
	dispatchTable map[string]func([]byte) []byte
}

// Create a new AMQP-RPC server on the given queue and channel.
// Note that you must call Start() to actually start the server
// listening for requests.
func NewAmqpRpcServer(serverQueue string, channel *amqp.Channel) *AmqpRpcServer {
	return &AmqpRpcServer{
		serverQueue:   serverQueue,
		channel:       channel,
		dispatchTable: make(map[string]func([]byte) []byte),
	}
}

func (rpc *AmqpRpcServer) Handle(method string, handler func([]byte) []byte) {
	rpc.dispatchTable[method] = handler
}

// Starts the AMQP-RPC server running in a separate thread.
// There is currently no Stop() method.
func (rpc *AmqpRpcServer) Start() (err error) {
	msgs, err := amqpSubscribe(rpc.channel, rpc.serverQueue)
	if err != nil {
		return
	}

	go func() {
		for msg := range msgs {
			// XXX-JWS: jws.Verify(body)
			cb, present := rpc.dispatchTable[msg.Type]
			log.Printf(" [s<] received %s(%s) [%s]", msg.Type, b64enc(msg.Body), msg.CorrelationId)
			if present {
				response := cb(msg.Body)
				log.Printf(" [s>] sending %s(%s) [%s]", msg.Type, b64enc(response), msg.CorrelationId)
				rpc.channel.Publish(
					AmqpExchange,
					msg.ReplyTo,
					AmqpMandatory,
					AmqpImmediate,
					amqp.Publishing{
						CorrelationId: msg.CorrelationId,
						Type:          msg.Type,
						Body:          response, // XXX-JWS: jws.Sign(privKey, body)
					})
			}
		}
	}()
	return
}

// An AMQP-RPC client sends requests to a specific server queue,
// and uses a dedicated response queue for responses.
//
// To implement specific functionality, using code uses the Dispatch()
// method to send a method name and body, and get back a response. So
// you end up with wrapper methods of the form:
//
// ```
//   request = /* serialize request to []byte */
//   response = <-AmqpRpcClient.Dispatch(method, request)
//   return /* deserialized response */
// ```
//
// Callers that don't care about the response can just call Dispatch()
// and ignore the return value.
//
// DispatchSync will manage the channel for you, and also enforce a
// timeout on the transaction (default 60 seconds)
type AmqpRpcClient struct {
	serverQueue string
	clientQueue string
	channel     *amqp.Channel
	pending     map[string]chan []byte
	timeout     time.Duration
}

func NewAmqpRpcClient(clientQueue, serverQueue string, channel *amqp.Channel) (rpc *AmqpRpcClient, err error) {
	rpc = &AmqpRpcClient{
		serverQueue: serverQueue,
		clientQueue: clientQueue,
		channel:     channel,
		pending:     make(map[string]chan []byte),
		timeout:     10 * time.Second,
	}

	// Subscribe to the response queue and dispatch
	msgs, err := amqpSubscribe(rpc.channel, clientQueue)
	if err != nil {
		return
	}

	go func() {
		for msg := range msgs {
			// XXX-JWS: jws.Sign(privKey, body)
			corrID := msg.CorrelationId
			responseChan, present := rpc.pending[corrID]

			log.Printf(" [c<] received %s(%s) [%s]", msg.Type, b64enc(msg.Body), corrID)
			if present {
				responseChan <- msg.Body
				delete(rpc.pending, corrID)
			}
		}
	}()

	return
}

func (rpc *AmqpRpcClient) SetTimeout(ttl time.Duration) {
	rpc.timeout = ttl
}

func (rpc *AmqpRpcClient) Dispatch(method string, body []byte) chan []byte {
	// Create a channel on which to direct the response
	// At least in some cases, it's important that this channel
	// be buffered to avoid deadlock
	responseChan := make(chan []byte, 1)
	corrID := newToken()
	rpc.pending[corrID] = responseChan

	// Send the request
	log.Printf(" [c>] sending %s(%s) [%s]", method, b64enc(body), corrID)
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

func (rpc *AmqpRpcClient) DispatchSync(method string, body []byte) (response []byte, err error) {
	select {
	case response = <-rpc.Dispatch(method, body):
		return
	case <-time.After(rpc.timeout):
		log.Printf(" [c!] AMQP-RPC timeout [%s]", method)
		err = errors.New("AMQP-RPC timeout")
		return
	}
	err = errors.New("Unknown error in SyncDispatch")
	return
}

func (rpc *AmqpRpcClient) SyncDispatchWithTimeout(method string, body []byte, ttl time.Duration) (response []byte, err error) {
	switch {

	}
	return
}
