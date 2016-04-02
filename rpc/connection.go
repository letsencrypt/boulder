package rpc

import (
	"fmt"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

func newAMQPConnector(
	queueName string,
	retryTimeoutBase time.Duration,
	retryTimeoutMax time.Duration,
) *amqpConnector {
	return &amqpConnector{
		queueName:        queueName,
		chMaker:          defaultChannelMaker{},
		clk:              clock.Default(),
		retryTimeoutBase: retryTimeoutBase,
		retryTimeoutMax:  retryTimeoutMax,
	}
}

// channelMaker encapsulates how to create an AMQP channel.
type channelMaker interface {
	makeChannel(conf *cmd.AMQPConfig) (amqpChannel, error)
}

type defaultChannelMaker struct{}

func (d defaultChannelMaker) makeChannel(conf *cmd.AMQPConfig) (amqpChannel, error) {
	return makeAmqpChannel(conf)
}

// amqpConnector encapsulates an AMQP channel and a subscription to a specific
// queue, plus appropriate locking for its members. It provides reconnect logic,
// and allows publishing via the channel onto an arbitrary queue.
type amqpConnector struct {
	mu               sync.RWMutex
	chMaker          channelMaker
	channel          amqpChannel
	queueName        string
	closeChan        chan *amqp.Error
	msgs             <-chan amqp.Delivery
	retryTimeoutBase time.Duration
	retryTimeoutMax  time.Duration
	clk              clock.Clock
}

func (ac *amqpConnector) messages() <-chan amqp.Delivery {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.msgs
}

func (ac *amqpConnector) closeChannel() chan *amqp.Error {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.closeChan
}

// connect attempts to connect to a channel and subscribe to the named queue,
// returning error if it fails. This is used at first startup, where we want to
// fail fast if we can't connect.
func (ac *amqpConnector) connect(config *cmd.AMQPConfig) error {
	channel, err := ac.chMaker.makeChannel(config)
	if err != nil {
		return fmt.Errorf("channel connect failed for %s: %s", ac.queueName, err)
	}
	msgs, err := amqpSubscribe(channel, ac.queueName, ac.queueName)
	if err != nil {
		return fmt.Errorf("queue subscribe failed for %s: %s", ac.queueName, err)
	}
	closeChan := channel.NotifyClose(make(chan *amqp.Error, 1))
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.channel = channel
	ac.msgs = msgs
	ac.closeChan = closeChan
	return nil
}

// reconnect attempts repeatedly to connect and subscribe to the named queue. It
// will loop forever until it succeeds. This is used for a running server, where
// we don't want to shut down because we lost our AMQP connection.
func (ac *amqpConnector) reconnect(config *cmd.AMQPConfig, log blog.SyslogWriter) {
	for i := 0; ; i++ {
		ac.clk.Sleep(core.RetryBackoff(i, ac.retryTimeoutBase, ac.retryTimeoutMax, 2))
		log.Info(fmt.Sprintf(" [!] attempting reconnect for %s", ac.queueName))
		err := ac.connect(config)
		if err != nil {
			log.Warning(fmt.Sprintf(" [!] %s", err))
			continue
		}
		break
	}
	log.Info(fmt.Sprintf(" [!] reconnect success for %s", ac.queueName))
	return
}

// cancel cancels the AMQP channel. Used for graceful shutdowns.
func (ac *amqpConnector) cancel() {
	ac.mu.RLock()
	channel := ac.channel
	ac.mu.RUnlock()
	channel.Cancel(consumerName, false)
}

// publish publishes a message onto the provided queue. We provide this wrapper
// because it requires locking around the read of ac.channel.
func (ac *amqpConnector) publish(queueName, corrID, expiration, replyTo, msgType string, body []byte) error {
	ac.mu.RLock()
	channel := ac.channel
	ac.mu.RUnlock()
	return channel.Publish(
		AmqpExchange,
		queueName,
		AmqpMandatory,
		AmqpImmediate,
		amqp.Publishing{
			Body:          body,
			CorrelationId: corrID,
			Expiration:    expiration,
			ReplyTo:       replyTo,
			Type:          msgType,
			Timestamp:     ac.clk.Now(),
		})
}

// amqpChannel defines the subset of amqp.Channel methods that we use in this
// package.
type amqpChannel interface {
	Cancel(consumer string, noWait bool) error
	Consume(queue, consumer string, autoAck, exclusive, noLocal, noWait bool, args amqp.Table) (<-chan amqp.Delivery, error)
	NotifyClose(c chan *amqp.Error) chan *amqp.Error
	Publish(exchange, key string, mandatory, immediate bool, msg amqp.Publishing) error
	QueueBind(name, key, exchange string, noWait bool, args amqp.Table) error
	QueueDeclare(name string, durable, autoDelete, exclusive, noWait bool, args amqp.Table) (amqp.Queue, error)
}
