// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package rpc

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/cmd"
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

// AMQPDeclareExchange attempts to declare the configured AMQP exchange,
// returning silently if already declared, erroring if nonexistant and
// unable to create.
func AMQPDeclareExchange(conn *amqp.Connection) error {
	var err error
	var ch *amqp.Channel
	log := blog.GetAuditLogger()

	ch, err = conn.Channel()
	if err != nil {
		log.Crit(fmt.Sprintf("Could not connect Channel: %s", err))
		return err
	}

	err = ch.ExchangeDeclarePassive(
		AmqpExchange,
		AmqpExchangeType,
		AmqpDurable,
		AmqpDeleteUnused,
		AmqpInternal,
		AmqpNoWait,
		nil)
	if err != nil {
		log.Info(fmt.Sprintf("Exchange %s does not exist on AMQP server, attempting to create. (err=%s)", AmqpExchange, err))

		// Channel is invalid at this point, so recreate
		ch.Close()
		ch, err = conn.Channel()
		if err != nil {
			log.Crit(fmt.Sprintf("Could not connect Channel: %s", err))
			return err
		}

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
			ch.Close()
			return err
		}
	}

	ch.Close()
	return err
}

// A simplified way to declare and subscribe to an AMQP queue
func amqpSubscribe(ch *amqp.Channel, name string, consumerName string, log *blog.AuditLogger) (<-chan amqp.Delivery, error) {
	var err error

	_, err = ch.QueueDeclare(
		name,
		AmqpDurable,
		AmqpDeleteUnused,
		AmqpExclusive,
		AmqpNoWait,
		nil)
	if err != nil {
		log.Crit(fmt.Sprintf("Could not declare queue: %s", err))
		return nil, err
	}

	routingKey := name

	err = ch.QueueBind(
		name,
		routingKey,
		AmqpExchange,
		false,
		nil)
	if err != nil {
		log.Crit(fmt.Sprintf("Could not bind to queue [%s]. NOTE: You may need to delete %s to re-trigger the bind attempt after fixing permissions, or manually bind the queue to %s.", name, name, routingKey))
		return nil, err
	}

	// A consumer name is used so that the specific consumer can be cancelled later
	// if signalled. If no name is used a UID is used which cannot be retrieved (as
	// far as I can tell).
	msgs, err := ch.Consume(
		name,
		consumerName,
		AmqpAutoAck,
		AmqpExclusive,
		AmqpNoLocal,
		AmqpNoWait,
		nil)
	if err != nil {
		log.Crit(fmt.Sprintf("Could not subscribe to queue: %s", err))
		return nil, err
	}

	return msgs, err
}

// AmqpRPCServer listens on a specified queue within an AMQP channel.
// When messages arrive on that queue, it dispatches them based on type,
// and returns the response to the ReplyTo queue.
//
// To implement specific functionality, using code should use the Handle
// method to add specific actions.
type AmqpRPCServer struct {
	serverQueue       string
	Channel           *amqp.Channel
	log               *blog.AuditLogger
	dispatchTable     map[string]func([]byte) ([]byte, error)
	connectionHandler func(*AmqpRPCServer)
	consumerName      string
	connected         bool
	done              bool
	dMu               sync.Mutex
}

// NewAmqpRPCServer creates a new RPC server for the given queue and will begin
// consuming requests from the queue. To start the server you must call Start().
func NewAmqpRPCServer(serverQueue string, handler func(*AmqpRPCServer)) (*AmqpRPCServer, error) {
	log := blog.GetAuditLogger()
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	consumerName := fmt.Sprintf("%s.%x", serverQueue, b)
	return &AmqpRPCServer{
		serverQueue:       serverQueue,
		log:               log,
		dispatchTable:     make(map[string]func([]byte) ([]byte, error)),
		connectionHandler: handler,
		consumerName:      consumerName,
	}, nil
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

// AmqpChannel sets a AMQP connection up using SSL if configuration is provided
func AmqpChannel(conf cmd.Config) (*amqp.Channel, error) {
	var conn *amqp.Connection
	var err error

	log := blog.GetAuditLogger()

	if conf.AMQP.Insecure == true {
		// If the Insecure flag is true, then just go ahead and connect
		conn, err = amqp.Dial(conf.AMQP.Server)
	} else {
		// The insecure flag is false or not set, so we need to load up the options
		log.Info("AMQPS: Loading TLS Options.")

		if strings.HasPrefix(conf.AMQP.Server, "amqps") == false {
			err = fmt.Errorf("AMQPS: Not using an AMQPS URL. To use AMQP instead of AMQPS, set insecure=true.")
			return nil, err
		}

		if conf.AMQP.TLS == nil {
			err = fmt.Errorf("AMQPS: No TLS configuration provided. To use AMQP instead of AMQPS, set insecure=true.")
			return nil, err
		}

		cfg := new(tls.Config)

		// If the configuration specified a certificate (or key), load them
		if conf.AMQP.TLS.CertFile != nil || conf.AMQP.TLS.KeyFile != nil {
			// But they have to give both.
			if conf.AMQP.TLS.CertFile == nil || conf.AMQP.TLS.KeyFile == nil {
				err = fmt.Errorf("AMQPS: You must set both of the configuration values AMQP.TLS.KeyFile and AMQP.TLS.CertFile")
				return nil, err
			}

			cert, err := tls.LoadX509KeyPair(*conf.AMQP.TLS.CertFile, *conf.AMQP.TLS.KeyFile)
			if err != nil {
				err = fmt.Errorf("AMQPS: Could not load Client Certificate or Key: %s", err)
				return nil, err
			}

			log.Info("AMQPS: Configured client certificate for AMQPS.")
			cfg.Certificates = append(cfg.Certificates, cert)
		}

		// If the configuration specified a CA certificate, make it the only
		// available root.
		if conf.AMQP.TLS.CACertFile != nil {
			cfg.RootCAs = x509.NewCertPool()

			ca, err := ioutil.ReadFile(*conf.AMQP.TLS.CACertFile)
			if err != nil {
				err = fmt.Errorf("AMQPS: Could not load CA Certificate: %s", err)
				return nil, err
			}
			cfg.RootCAs.AppendCertsFromPEM(ca)
			log.Info("AMQPS: Configured CA certificate for AMQPS.")
		}

		conn, err = amqp.DialTLS(conf.AMQP.Server, cfg)
	}

	if err != nil {
		return nil, err
	}

	err = AMQPDeclareExchange(conn)
	if err != nil {
		return nil, err
	}

	return conn.Channel()
}

func (rpc *AmqpRPCServer) processMessage(msg amqp.Delivery) {
	// XXX-JWS: jws.Verify(body)
	cb, present := rpc.dispatchTable[msg.Type]
	rpc.log.Info(fmt.Sprintf(" [s<][%s][%s] received %s(%s) [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, core.B64enc(msg.Body), msg.CorrelationId))
	if !present {
		// AUDIT[ Misrouted Messages ] f523f21f-12d2-4c31-b2eb-ee4b7d96d60e
		rpc.log.Audit(fmt.Sprintf(" [s<][%s][%s] Misrouted message: %s - %s - %s", rpc.serverQueue, msg.ReplyTo, msg.Type, core.B64enc(msg.Body), msg.CorrelationId))
		return
	}
	var response RPCResponse
	var err error
	response.ReturnVal, err = cb(msg.Body)
	response.Error = wrapError(err)
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		rpc.log.Audit(fmt.Sprintf(" [s>][%s][%s] Error condition marshalling RPC response %s [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, msg.CorrelationId))
		return
	}
	if response.Error.Value != "" {
		rpc.log.Info(fmt.Sprintf(" [s>][%s][%s] %s failed, replying: %s (%s) [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, response.Error.Value, response.Error.Type, msg.CorrelationId))
	}
	rpc.log.Debug(fmt.Sprintf(" [s>][%s][%s] replying %s(%s) [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, core.B64enc(jsonResponse), msg.CorrelationId))
	rpc.Channel.Publish(
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

// Start starts the AMQP-RPC server and handles reconnections, this will block
// until a fatal error is returned or AmqpRPCServer.Stop() is called and all
// remaining messages are processed.
func (rpc *AmqpRPCServer) Start(c cmd.Config) error {
	go rpc.catchSignals()
	for {
		rpc.dMu.Lock()
		if rpc.done {
			rpc.dMu.Unlock()
			break
		}
		rpc.dMu.Unlock()
		var err error
		rpc.Channel, err = AmqpChannel(c)
		if err != nil {
			return err
		}
		rpc.connectionHandler(rpc)

		msgs, err := amqpSubscribe(rpc.Channel, rpc.serverQueue, rpc.consumerName, rpc.log)
		if err != nil {
			return err
		}
		rpc.connected = true
		rpc.log.Info(" [!] Connected to AMQP")

		closeChan := rpc.Channel.NotifyClose(make(chan *amqp.Error, 1))
		for blocking := true; blocking; {
			select {
			case msg, ok := <-msgs:
				if ok {
					rpc.processMessage(msg)
				} else {
					// chan has been closed by rpc.channel.Cancel
					rpc.log.Info(" [!] Finished processing messages")
					return nil
				}
			case err = <-closeChan:
				rpc.connected = false
				rpc.log.Warning(fmt.Sprintf(" [!] AMQP Channel closed, will reconnect in 5 seconds: [%s]", err))
				time.Sleep(time.Second * 5)
				blocking = false
			}
		}
	}
	return nil
}

var signalToName = map[os.Signal]string{
	syscall.SIGTERM: "SIGTERM",
	syscall.SIGINT:  "SIGINT",
	syscall.SIGHUP:  "SIGHUP",
}

func (rpc *AmqpRPCServer) catchSignals() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGHUP)

	sig := <-sigChan
	rpc.log.Info(fmt.Sprintf(" [!] Caught %s", signalToName[sig]))
	rpc.Stop()
	signal.Stop(sigChan)
}

// Stop gracefully stops the AmqpRPCServer, after calling AmqpRPCServer.Start will
// continue blocking until it has processed any messages that have already been
// retrieved.
func (rpc *AmqpRPCServer) Stop() {
	if rpc.connected {
		rpc.log.Info(" [!] Shutting down RPC server, stopping new deliveries and processing remaining messages")
		rpc.Channel.Cancel(rpc.consumerName, false)
	} else {
		rpc.log.Info("[!] Shutting down RPC server, nothing to clean up")
		rpc.dMu.Lock()
		rpc.done = true
		rpc.dMu.Unlock()
	}
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
	msgs, err := amqpSubscribe(rpc.channel, clientQueue, "", rpc.log)
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
