package rpc

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jmhodges/clock"
	"github.com/streadway/amqp"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/probs"
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
	consumerName     = "boulder"
)

// A simplified way to declare and subscribe to an AMQP queue
func amqpSubscribe(ch amqpChannel, name, routingKey string) (<-chan amqp.Delivery, error) {
	var err error

	_, err = ch.QueueDeclare(
		name,
		AmqpDurable,
		AmqpDeleteUnused,
		AmqpExclusive,
		AmqpNoWait,
		nil)
	if err != nil {
		return nil, fmt.Errorf("could not declare queue: %s", err)
	}

	err = ch.QueueBind(
		name,
		routingKey,
		AmqpExchange,
		false,
		nil)
	if err != nil {
		err = fmt.Errorf(
			"Could not bind to queue %s: %s. NOTE: You may need to delete it to re-trigger the bind attempt after fixing permissions, or manually bind the queue to %s.",
			err, name, routingKey)
		return nil, err
	}

	msgs, err := ch.Consume(
		name,
		consumerName,
		AmqpAutoAck,
		AmqpExclusive,
		AmqpNoLocal,
		AmqpNoWait,
		nil)
	if err != nil {
		return nil, fmt.Errorf("Could not subscribe to queue: %s", err)
	}

	return msgs, nil
}

// DeliveryHandler is a function that will process an amqp.DeliveryHandler
type DeliveryHandler func(amqp.Delivery)
type messageHandler func(context.Context, []byte) ([]byte, error)

// AmqpRPCServer listens on a specified queue within an AMQP channel.
// When messages arrive on that queue, it dispatches them based on type,
// and returns the response to the ReplyTo queue.
//
// To implement specific functionality, using code should use the Handle
// method to add specific actions.
type AmqpRPCServer struct {
	serverQueue    string
	connection     *amqpConnector
	log            blog.Logger
	handleDelivery DeliveryHandler
	// Servers that just care about messages (method + body) add entries to
	// dispatchTable
	dispatchTable                  map[string]messageHandler
	connected                      bool
	done                           bool
	mu                             sync.RWMutex
	currentGoroutines              int64
	maxConcurrentRPCServerRequests int64
	tooManyRequestsResponse        []byte
	stats                          metrics.Scope
	clk                            clock.Clock
}

const wildcardRoutingKey = "#"

// NewAmqpRPCServer creates a new RPC server for the given queue and will begin
// consuming requests from the queue. To start the server you must call Start().
func NewAmqpRPCServer(
	amqpConf *cmd.AMQPConfig,
	maxConcurrentRPCServerRequests int64,
	stats metrics.Scope,
	log blog.Logger,
) (*AmqpRPCServer, error) {
	stats = stats.NewScope("RPC")

	reconnectBase := amqpConf.ReconnectTimeouts.Base.Duration
	if reconnectBase == 0 {
		reconnectBase = 20 * time.Millisecond
	}
	reconnectMax := amqpConf.ReconnectTimeouts.Max.Duration
	if reconnectMax == 0 {
		reconnectMax = time.Minute
	}

	return &AmqpRPCServer{
		serverQueue:                    amqpConf.ServiceQueue,
		connection:                     newAMQPConnector(amqpConf.ServiceQueue, reconnectBase, reconnectMax),
		log:                            log,
		dispatchTable:                  make(map[string]messageHandler),
		maxConcurrentRPCServerRequests: maxConcurrentRPCServerRequests,
		clk:   clock.Default(),
		stats: stats,
	}, nil
}

// Handle registers a function to handle a particular method.
func (rpc *AmqpRPCServer) Handle(method string, handler messageHandler) {
	rpc.mu.Lock()
	rpc.dispatchTable[method] = handler
	rpc.mu.Unlock()
}

// rpcError is a JSON wrapper for error as it cannot be un/marshalled
// due to type interface{}.
type rpcError struct {
	Value      string `json:"value"`
	Type       string `json:"type,omitempty"`
	HTTPStatus int    `json:"status,omitempty"`
}

// Wraps an error in a rpcError so it can be marshalled to
// JSON.
func wrapError(err error) *rpcError {
	if err != nil {
		wrapped := &rpcError{
			Value: err.Error(),
		}
		switch terr := err.(type) {
		case core.InternalServerError:
			wrapped.Type = "InternalServerError"
		case core.NotSupportedError:
			wrapped.Type = "NotSupportedError"
		case core.MalformedRequestError:
			wrapped.Type = "MalformedRequestError"
		case core.UnauthorizedError:
			wrapped.Type = "UnauthorizedError"
		case core.NotFoundError:
			wrapped.Type = "NotFoundError"
		case core.SignatureValidationError:
			wrapped.Type = "SignatureValidationError"
		case core.NoSuchRegistrationError:
			wrapped.Type = "NoSuchRegistrationError"
		case core.TooManyRPCRequestsError:
			wrapped.Type = "TooManyRPCRequestsError"
		case core.RateLimitedError:
			wrapped.Type = "RateLimitedError"
		case *probs.ProblemDetails:
			wrapped.Type = string(terr.Type)
			wrapped.Value = terr.Detail
			wrapped.HTTPStatus = terr.HTTPStatus
		}
		return wrapped
	}
	return nil
}

// Unwraps a rpcError and returns the correct error type.
func unwrapError(rpcError *rpcError) error {
	if rpcError != nil {
		switch rpcError.Type {
		case "InternalServerError":
			return core.InternalServerError(rpcError.Value)
		case "NotSupportedError":
			return core.NotSupportedError(rpcError.Value)
		case "MalformedRequestError":
			return core.MalformedRequestError(rpcError.Value)
		case "UnauthorizedError":
			return core.UnauthorizedError(rpcError.Value)
		case "NotFoundError":
			return core.NotFoundError(rpcError.Value)
		case "SignatureValidationError":
			return core.SignatureValidationError(rpcError.Value)
		case "NoSuchRegistrationError":
			return core.NoSuchRegistrationError(rpcError.Value)
		case "TooManyRPCRequestsError":
			return core.TooManyRPCRequestsError(rpcError.Value)
		case "RateLimitedError":
			return core.RateLimitedError(rpcError.Value)
		default:
			if strings.HasPrefix(rpcError.Type, "urn:") {
				return &probs.ProblemDetails{
					Type:       probs.ProblemType(rpcError.Type),
					Detail:     rpcError.Value,
					HTTPStatus: rpcError.HTTPStatus,
				}
			}
			return errors.New(rpcError.Value)
		}
	}
	return nil
}

// rpcResponse is a stuct for wire-representation of response messages
// used by DispatchSync
type rpcResponse struct {
	ReturnVal []byte    `json:"returnVal"`
	Error     *rpcError `json:"error,omitempty"`
}

// Hack: Some of our RPCs return DER directly. If we log it naively it will
// just be a bunch of numbers. It's easy to detect DER, so we use this function
// before logging to base64-encode anything that looks like DER.
func safeDER(input []byte) string {
	if len(input) > 0 && input[0] == 0x30 {
		return string(base64.RawStdEncoding.EncodeToString(input))
	}
	return string(input)
}

// Used for debug logging
func (r rpcResponse) debugString() string {
	ret := safeDER(r.ReturnVal)
	if r.Error == nil {
		return ret
	}
	return fmt.Sprintf("%s, RPCERR: %v", ret, r.Error)
}

// makeAmqpChannel sets an AMQP connection up using SSL if configuration is provided
func makeAmqpChannel(conf *cmd.AMQPConfig) (*amqp.Channel, error) {
	var conn *amqp.Connection
	var err error

	log := blog.Get()

	serverURL, err := conf.ServerURL()
	if err != nil {
		return nil, err
	}

	if conf.Insecure == true {
		// If the Insecure flag is true, then just go ahead and connect
		conn, err = amqp.Dial(serverURL)
	} else {
		// The insecure flag is false or not set, so we need to load up the options
		log.Info("AMQPS: Loading TLS Options.")

		if strings.HasPrefix(serverURL, "amqps") == false {
			err = fmt.Errorf("AMQPS: Not using an AMQPS URL. To use AMQP instead of AMQPS, set insecure=true")
			return nil, err
		}

		if conf.TLS == nil {
			err = fmt.Errorf("AMQPS: No TLS configuration provided. To use AMQP instead of AMQPS, set insecure=true")
			return nil, err
		}

		cfg := new(tls.Config)

		// If the configuration specified a certificate (or key), load them
		if conf.TLS.CertFile != nil || conf.TLS.KeyFile != nil {
			// But they have to give both.
			if conf.TLS.CertFile == nil || conf.TLS.KeyFile == nil {
				err = fmt.Errorf("AMQPS: You must set both of the configuration values AMQP.TLS.KeyFile and AMQP.TLS.CertFile")
				return nil, err
			}

			cert, err := tls.LoadX509KeyPair(*conf.TLS.CertFile, *conf.TLS.KeyFile)
			if err != nil {
				err = fmt.Errorf("AMQPS: Could not load Client Certificate or Key: %s", err)
				return nil, err
			}

			log.Info("AMQPS: Configured client certificate for AMQPS.")
			cfg.Certificates = append(cfg.Certificates, cert)
		}

		// If the configuration specified a CA certificate, make it the only
		// available root.
		if conf.TLS.CACertFile != nil {
			cfg.RootCAs = x509.NewCertPool()

			ca, err := ioutil.ReadFile(*conf.TLS.CACertFile)
			if err != nil {
				err = fmt.Errorf("AMQPS: Could not load CA Certificate: %s", err)
				return nil, err
			}
			cfg.RootCAs.AppendCertsFromPEM(ca)
			log.Info("AMQPS: Configured CA certificate for AMQPS.")
		}

		conn, err = amqp.DialTLS(serverURL, cfg)
	}

	if err != nil {
		return nil, err
	}

	return conn.Channel()
}

func (rpc *AmqpRPCServer) processMessage(msg amqp.Delivery) {
	ctx := context.TODO()

	// XXX-JWS: jws.Verify(body)
	cb, present := rpc.dispatchTable[msg.Type]
	rpc.log.Debug(fmt.Sprintf(" [s<][%s][%s] received %s(%s) [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, safeDER(msg.Body), msg.CorrelationId))
	if !present {
		// AUDIT[ Misrouted Messages ] f523f21f-12d2-4c31-b2eb-ee4b7d96d60e
		rpc.log.AuditErr(fmt.Sprintf(" [s<][%s][%s] Misrouted message: %s - %s - %s", rpc.serverQueue, msg.ReplyTo, msg.Type, safeDER(msg.Body), msg.CorrelationId))
		return
	}
	var response rpcResponse
	var err error
	response.ReturnVal, err = cb(ctx, msg.Body)
	response.Error = wrapError(err)
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		rpc.log.AuditErr(fmt.Sprintf(" [s>][%s][%s] Error condition marshalling RPC response %s [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, msg.CorrelationId))
		return
	}
	rpc.log.Debug(fmt.Sprintf(" [s>][%s][%s] replying %s: %s [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, response.debugString(), msg.CorrelationId))
	err = rpc.connection.publish(
		msg.ReplyTo,
		msg.CorrelationId,
		"30000",
		"",
		msg.Type,
		jsonResponse)
	if err != nil {
		rpc.log.AuditErr(fmt.Sprintf(" [s>][%s][%s] Error condition replying to RPC %s [%s]", rpc.serverQueue, msg.ReplyTo, msg.Type, msg.CorrelationId))
	}
}

func (rpc *AmqpRPCServer) replyTooManyRequests(msg amqp.Delivery) error {
	return rpc.connection.publish(
		msg.ReplyTo,
		msg.CorrelationId,
		"1000",
		"",
		msg.Type,
		rpc.tooManyRequestsResponse)
}

// Start starts the AMQP-RPC server and handles reconnections, this will block
// until a fatal error is returned or AmqpRPCServer.Stop() is called and all
// remaining messages are processed.
func (rpc *AmqpRPCServer) Start(c *cmd.AMQPConfig) error {
	tooManyGoroutines := rpcResponse{
		Error: wrapError(core.TooManyRPCRequestsError("RPC server has spawned too many Goroutines")),
	}
	tooManyRequestsResponse, err := json.Marshal(tooManyGoroutines)
	if err != nil {
		return err
	}
	rpc.tooManyRequestsResponse = tooManyRequestsResponse

	err = rpc.connection.connect(c)
	if err != nil {
		return err
	}
	rpc.mu.Lock()
	rpc.connected = true
	rpc.mu.Unlock()

	go rpc.catchSignals()

	for {
		select {
		case msg, ok := <-rpc.connection.messages():
			if ok {
				rpc.stats.TimingDuration(fmt.Sprintf("MessageLag.%s", rpc.serverQueue), rpc.clk.Now().Sub(msg.Timestamp))
				if rpc.maxConcurrentRPCServerRequests > 0 && atomic.LoadInt64(&rpc.currentGoroutines) >= rpc.maxConcurrentRPCServerRequests {
					_ = rpc.replyTooManyRequests(msg)
					rpc.stats.Inc(fmt.Sprintf("CallsDropped.%s", rpc.serverQueue), 1)
					break // this breaks the select, not the for
				}
				rpc.stats.Inc(fmt.Sprintf("Traffic.Rx.%s", rpc.serverQueue), int64(len(msg.Body)))
				go func() {
					atomic.AddInt64(&rpc.currentGoroutines, 1)
					defer atomic.AddInt64(&rpc.currentGoroutines, -1)
					startedProcessing := rpc.clk.Now()
					if rpc.handleDelivery != nil {
						rpc.handleDelivery(msg)
					} else {
						rpc.processMessage(msg)
					}
					rpc.stats.TimingDuration(fmt.Sprintf("ServerProcessingLatency.%s", msg.Type), time.Since(startedProcessing))
				}()
			} else {
				rpc.mu.RLock()
				if rpc.done {
					// chan has been closed by rpc.connection.Cancel
					rpc.log.Info(" [!] Finished processing messages")
					rpc.mu.RUnlock()
					return nil
				}
				rpc.mu.RUnlock()
				rpc.log.Info(" [!] Got channel close, but no signal to shut down. Continuing.")
			}
		case err = <-rpc.connection.closeChannel():
			rpc.log.Info(fmt.Sprintf(" [!] Server channel closed: %s", rpc.serverQueue))
			rpc.connection.reconnect(c, rpc.log)
		}
	}
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
	rpc.mu.Lock()
	rpc.done = true
	rpc.mu.Unlock()
	if rpc.connected {
		rpc.log.Info(" [!] Shutting down RPC server, stopping new deliveries and processing remaining messages")
		rpc.connection.cancel()
	} else {
		rpc.log.Info("[!] Shutting down RPC server, nothing to clean up")
	}
}

// AmqpRPCCLient is an AMQP-RPC client that sends requests to a specific server
// queue, and uses a dedicated response queue for responses.
//
// To implement specific functionality, using code uses the DispatchSync()
// method to send a method name and body, and get back a response. So
// you end up with wrapper methods of the form:
//
// ```
//   request = /* serialize request to []byte */
//   response = AmqpRPCCLient.Dispatch(method, request)
//   return /* deserialized response */
// ```
//
// DispatchSync will manage the channel for you, and also enforce a
// timeout on the transaction.
type AmqpRPCCLient struct {
	serverQueue string
	clientQueue string
	connection  *amqpConnector
	timeout     time.Duration
	log         blog.Logger

	mu      sync.RWMutex
	pending map[string]chan []byte

	stats metrics.Scope
}

// NewAmqpRPCClient constructs an RPC client using AMQP
func NewAmqpRPCClient(
	clientQueuePrefix string,
	amqpConf *cmd.AMQPConfig,
	rpcConf *cmd.RPCServerConfig,
	stats metrics.Scope,
) (rpc *AmqpRPCCLient, err error) {
	stats = stats.NewScope("RPC")
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	randID := make([]byte, 3)
	_, err = rand.Read(randID)
	if err != nil {
		return nil, err
	}
	clientQueue := fmt.Sprintf("%s.%s.%x", clientQueuePrefix, hostname, randID)

	reconnectBase := amqpConf.ReconnectTimeouts.Base.Duration
	if reconnectBase == 0 {
		reconnectBase = 20 * time.Millisecond
	}
	reconnectMax := amqpConf.ReconnectTimeouts.Max.Duration
	if reconnectMax == 0 {
		reconnectMax = time.Minute
	}

	timeout := rpcConf.RPCTimeout.Duration
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	rpc = &AmqpRPCCLient{
		serverQueue: rpcConf.Server,
		clientQueue: clientQueue,
		connection:  newAMQPConnector(clientQueue, reconnectBase, reconnectMax),
		pending:     make(map[string]chan []byte),
		timeout:     timeout,
		log:         blog.Get(),
		stats:       stats,
	}

	err = rpc.connection.connect(amqpConf)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case msg, ok := <-rpc.connection.messages():
				if ok {
					corrID := msg.CorrelationId
					rpc.mu.RLock()
					responseChan, present := rpc.pending[corrID]
					rpc.mu.RUnlock()

					if !present {
						// occurs when a request is timed out and the arrives
						// afterwards
						stats.Inc("AfterTimeoutResponseArrivals."+clientQueuePrefix, 1)
						continue
					}

					responseChan <- msg.Body
					rpc.mu.Lock()
					delete(rpc.pending, corrID)
					rpc.mu.Unlock()
				} else {
					// chan has been closed by rpc.connection.Cancel
					rpc.log.Info(fmt.Sprintf(" [!] Client reply channel closed: %s", rpc.clientQueue))
					continue
				}
			case err = <-rpc.connection.closeChannel():
				rpc.log.Info(fmt.Sprintf(" [!] Client reply channel closed : %s", rpc.clientQueue))
				rpc.connection.reconnect(amqpConf, rpc.log)
			}
		}
	}()

	return rpc, err
}

// dispatch sends a body to the destination, and returns the id for the request
// that can be used to correlate it with responses, and a response channel that
// can be used to monitor for responses, or discarded for one-shot actions.
func (rpc *AmqpRPCCLient) dispatch(method string, body []byte) (string, chan []byte, error) {
	// Create a channel on which to direct the response
	// At least in some cases, it's important that this channel
	// be buffered to avoid deadlock
	responseChan := make(chan []byte, 1)
	corrIDBytes := make([]byte, 8)
	_, err := rand.Read(corrIDBytes)
	if err != nil {
		panic("randomness failed")
	}
	corrID := base64.RawURLEncoding.EncodeToString(corrIDBytes)
	rpc.mu.Lock()
	rpc.pending[corrID] = responseChan
	rpc.mu.Unlock()

	// Send the request
	rpc.log.Debug(fmt.Sprintf(" [c>][%s] requesting %s(%s) [%s]", rpc.clientQueue, method, safeDER(body), corrID))
	err = rpc.connection.publish(
		rpc.serverQueue,
		corrID,
		"30000",
		rpc.clientQueue,
		method,
		body)

	if err != nil {
		return "", nil, err
	}

	return corrID, responseChan, nil
}

// DispatchSync sends a body to the destination, and blocks waiting on a response.
func (rpc *AmqpRPCCLient) DispatchSync(method string, body []byte) (response []byte, err error) {
	rpc.stats.Inc(fmt.Sprintf("Traffic.Tx.%s", rpc.serverQueue), int64(len(body)))
	callStarted := time.Now()
	corrID, responseChan, err := rpc.dispatch(method, body)
	if err != nil {
		return nil, err
	}
	select {
	case jsonResponse := <-responseChan:
		var rpcResponse rpcResponse
		err = json.Unmarshal(jsonResponse, &rpcResponse)
		rpc.log.Debug(fmt.Sprintf(" [c<][%s] response %s: %s [%s]", rpc.clientQueue, method, rpcResponse.debugString(), corrID))
		if err != nil {
			return nil, err
		}
		err = unwrapError(rpcResponse.Error)
		if err != nil {
			rpc.stats.Inc(fmt.Sprintf("ClientCallLatency.%s.Error", method), 1)
			return nil, err
		}
		rpc.stats.TimingDuration(fmt.Sprintf("ClientCallLatency.%s.Success", method), time.Since(callStarted))
		response = rpcResponse.ReturnVal
		return response, nil
	case <-time.After(rpc.timeout):
		rpc.stats.TimingDuration(fmt.Sprintf("ClientCallLatency.%s.Timeout", method), time.Since(callStarted))
		rpc.log.Warning(fmt.Sprintf(" [c!][%s] AMQP-RPC timeout [%s]", rpc.clientQueue, method))
		rpc.mu.Lock()
		delete(rpc.pending, corrID)
		rpc.mu.Unlock()
		err = errors.New("AMQP-RPC timeout")
		return nil, err
	}
}
