package rpc

import (
	"errors"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/golang/mock/gomock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/mocks"
)

// mockChannelMaker always returns the given amqpChannel
type mockChannelMaker struct {
	channel amqpChannel
}

func (m mockChannelMaker) makeChannel(conf *cmd.AMQPConfig) (amqpChannel, error) {
	return m.channel, nil
}

func setup(t *testing.T) (*amqpConnector, *MockamqpChannel, func()) {
	mockCtrl := gomock.NewController(t)

	mockChannel := NewMockamqpChannel(mockCtrl)
	ac := amqpConnector{
		chMaker: mockChannelMaker{
			channel: mockChannel,
		},
		queueName:        "fooqueue",
		retryTimeoutBase: time.Second,
		clk:              clock.NewFake(),
	}
	return &ac, mockChannel, func() { mockCtrl.Finish() }
}

func TestConnect(t *testing.T) {
	ac, mockChannel, finish := setup(t)
	defer finish()
	mockChannel.EXPECT().QueueDeclare(
		"fooqueue", AmqpDurable, AmqpDeleteUnused, AmqpExclusive, AmqpNoWait, nil)
	mockChannel.EXPECT().QueueBind("fooqueue", "fooqueue", AmqpExchange, false, nil)
	mockChannel.EXPECT().Consume("fooqueue", consumerName, AmqpAutoAck, AmqpExclusive, AmqpNoLocal, AmqpNoWait, nil).Return(make(<-chan amqp.Delivery), nil)
	mockChannel.EXPECT().NotifyClose(gomock.Any()).Return(make(chan *amqp.Error))
	err := ac.connect(&cmd.AMQPConfig{})
	if err != nil {
		t.Fatalf("failed to connect: %s", err)
	}
	if ac.channel != mockChannel {
		t.Errorf("ac.channel was not equal to mockChannel")
	}
	if ac.messages() == nil {
		t.Errorf("ac.msgs was not initialized")
	}
	if ac.closeChannel() == nil {
		t.Errorf("ac.closeChan was not initialized")
	}
}

func TestConnectFail(t *testing.T) {
	ac, mockChannel, finish := setup(t)
	defer finish()
	mockChannel.EXPECT().QueueDeclare(
		"fooqueue", AmqpDurable, AmqpDeleteUnused, AmqpExclusive, AmqpNoWait, nil).Return(amqp.Queue{}, errors.New("fail"))
	err := ac.connect(&cmd.AMQPConfig{})
	if err == nil {
		t.Fatalf("connect should have errored but did not")
	}
}

func TestReconnect(t *testing.T) {
	ac, mockChannel, finish := setup(t)
	defer finish()

	// Override the clock so the sleep calls are instantaneous, regardless of what
	// the retry calls say.
	ac.clk = clock.NewFake()
	ac.retryTimeoutBase = time.Second
	ac.retryTimeoutMax = time.Second

	mockChannel.EXPECT().QueueDeclare(
		"fooqueue", AmqpDurable, AmqpDeleteUnused, AmqpExclusive, AmqpNoWait, nil).AnyTimes()
	mockChannel.EXPECT().QueueBind("fooqueue", "fooqueue", AmqpExchange, false, nil).Times(3).Return(errors.New("fail"))
	mockChannel.EXPECT().QueueBind("fooqueue", "fooqueue", AmqpExchange, false, nil).Return(nil)
	mockChannel.EXPECT().Consume("fooqueue", consumerName, AmqpAutoAck, AmqpExclusive, AmqpNoLocal, AmqpNoWait, nil).Return(make(<-chan amqp.Delivery), nil)
	mockChannel.EXPECT().NotifyClose(gomock.Any()).Return(make(chan *amqp.Error))

	log = mocks.UseMockLog()

	ac.reconnect(&cmd.AMQPConfig{}, log)
	if ac.channel != mockChannel {
		t.Errorf("ac.channel was not equal to mockChannel")
	}
	if ac.msgs == nil {
		t.Errorf("ac.msgs was not initialized")
	}
	if ac.closeChan == nil {
		t.Errorf("ac.closeChan was not initialized")
	}
}

func TestCancel(t *testing.T) {
	ac, mockChannel, finish := setup(t)
	defer finish()
	// Since we're skipping the connect step, fake it by assigning directly to
	// channel.
	ac.channel = mockChannel
	mockChannel.EXPECT().Cancel(consumerName, false)
	ac.cancel()
}

func TestPublish(t *testing.T) {
	ac, mockChannel, finish := setup(t)
	defer finish()
	ac.channel = mockChannel
	mockChannel.EXPECT().Publish(
		AmqpExchange,
		"fooqueue",
		AmqpMandatory,
		AmqpImmediate,
		amqp.Publishing{
			Body:          []byte("body"),
			CorrelationId: "03c52e",
			Expiration:    "3000",
			ReplyTo:       "replyTo",
			Type:          "testMsg",
			Timestamp:     ac.clk.Now(),
		})
	ac.publish("fooqueue", "03c52e", "3000", "replyTo", "testMsg", []byte("body"))
}
