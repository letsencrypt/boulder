package beeline

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/honeycombio/libhoney-go/transmission"

	"github.com/honeycombio/beeline-go/client"
	"github.com/honeycombio/beeline-go/propagation"
	"github.com/honeycombio/beeline-go/sample"
	"github.com/honeycombio/beeline-go/trace"
	libhoney "github.com/honeycombio/libhoney-go"
)

const (
	defaultWriteKey       = "apikey-placeholder"
	defaultDatasetClassic = "beeline-go"
	defaultDataset        = "unknown_service"
	defaultServiceName    = "unknown_service"
	defaultSampleRate     = 1
	warningColor          = "\033[1;33m%s\033[0m"
)

// Config is the place where you configure your Honeycomb write key and dataset
// name. WriteKey is the only required field in order to actually send events to
// Honeycomb.
type Config struct {
	// Writekey is your Honeycomb authentication token, available from
	// https://ui.honeycomb.io/account. default: apikey-placeholder
	WriteKey string
	// Dataset is the name of the Honeycomb dataset to which events will be
	// sent. default: beeline-go
	Dataset string
	// Service Name identifies your application. While optional, setting this
	// field is extremely valuable when you instrument multiple services. If set
	// it will be added to all events as `service_name`
	ServiceName string
	// SamplRate is a positive integer indicating the rate at which to sample
	// events. Default sampling is at the trace level - entire traces will be
	// kept or dropped. default: 1 (meaning no sampling)
	SampleRate uint
	// SamplerHook is a function that will get run with the contents of each
	// event just before sending the event to Honeycomb. Register a function
	// with this config option to have manual control over sampling within the
	// beeline. The function should return true if the event should be kept and
	// false if it should be dropped.  If it should be kept, the returned
	// integer is the sample rate that has been applied. The SamplerHook
	// overrides the default sampler. Runs before the PresendHook.
	SamplerHook func(map[string]interface{}) (bool, int)
	// PresendHook is a function call that will get run with the contents of
	// each event just before sending them to Honeycomb. The function registered
	// here may mutate the map passed in to add, change, or drop fields from the
	// event before it gets sent to Honeycomb. Does not get invoked if the event
	// is going to be dropped because of sampling. Runs after the SamplerHook.
	PresendHook func(map[string]interface{})

	// APIHost is the hostname for the Honeycomb API server to which to send
	// this event. default: https://api.honeycomb.io/
	// Not used if client is set
	APIHost string
	// STDOUT when set to true will print events to STDOUT *instead* of sending
	// them to honeycomb; useful for development. default: false
	// Not used if client is set
	STDOUT bool
	// Mute when set to true will disable Honeycomb entirely; useful for tests
	// and CI. default: false
	// Not used if client is set
	Mute bool
	// Debug will emit verbose logging to STDOUT when true. If you're having
	// trouble getting the beeline to work, set this to true in a dev
	// environment.
	Debug bool
	// MaxBatchSize, if set, will override the default number of events
	// (libhoney.DefaultMaxBatchSize) that are sent per batch.
	// Not used if client is set
	MaxBatchSize uint
	// BatchTimeout, if set, will override the default time (libhoney.DefaultBatchTimeout)
	// for sending batches that have not been fully-filled.
	// Not used if client is set
	BatchTimeout time.Duration
	// MaxConcurrentBatches, if set, will override the default number of
	// goroutines (libhoney.DefaultMaxConcurrentBatches) that are used to send batches of events in parallel.
	// Not used if client is set
	MaxConcurrentBatches uint
	// PendingWorkCapacity overrides the default event queue size (libhoney.DefaultPendingWorkCapacity).
	// If the queue is full, events will be dropped.
	// Not used if client is set
	PendingWorkCapacity uint

	// Client, if specified, allows overriding the default client used to send events to Honeycomb
	// If set, overrides many fields in this config - see descriptions
	Client *libhoney.Client

	// PprofTagging controls whether span IDs should be propagated to pprof.
	PprofTagging bool
}

func IsClassicKey(config Config) bool {
	// classic key has 32 characters
	return len(config.WriteKey) == 32
}

// Init intializes the honeycomb instrumentation library.
func Init(config Config) {
	userAgentAddition := fmt.Sprintf("beeline/%s", version)

	if config.WriteKey == "" {
		fmt.Println("WARN: Missing API Key.")
		config.WriteKey = defaultWriteKey
	}

	if config.ServiceName == "" {
		fmt.Println("WARN: Missing service name.")
		// set default service name if not provided
		config.ServiceName = defaultServiceName
		if executable, err := os.Executable(); err == nil {
			// try to append default with process name
			config.ServiceName = defaultServiceName + ":" + filepath.Base(executable)
		} else {
			// fall back to language if process name is unavailable
			config.ServiceName = defaultServiceName + ":go"
		}
	}

	if IsClassicKey(config) {
		// if classic and missing dataset, warn on that
		if config.Dataset == "" {
			fmt.Println("WARN: Missing dataset. Data will be sent to:", defaultDatasetClassic)
			config.Dataset = defaultDatasetClassic
		}
	} else {
		// non classic key will ignore dataset, warn if configured
		if config.Dataset != "" {
			fmt.Println("WARN: Dataset is ignored in favor of service name. Data will be sent to service name:", config.ServiceName)
		}
		// set dataset based on service name
		config.Dataset = config.ServiceName

		if strings.TrimSpace(config.Dataset) != config.Dataset {
			// whitespace detected. trim whitespace, warn on diff
			fmt.Println("WARN: Service name has unexpected spaces")
			config.Dataset = strings.TrimSpace(config.Dataset)
		}
		if config.Dataset == "" {
			config.Dataset = defaultDataset
		}
		// truncate to unknown_service for dataset
		if strings.HasPrefix(config.Dataset, "unknown_service") {
			config.Dataset = defaultDataset
		}
	}

	if config.SampleRate == 0 {
		config.SampleRate = defaultSampleRate
	}
	if config.MaxBatchSize == 0 {
		config.MaxBatchSize = libhoney.DefaultMaxBatchSize
	}
	if config.BatchTimeout == 0 {
		config.BatchTimeout = libhoney.DefaultBatchTimeout
	}
	if config.MaxConcurrentBatches == 0 {
		config.MaxConcurrentBatches = libhoney.DefaultMaxConcurrentBatches
	}
	if config.PendingWorkCapacity == 0 {
		config.PendingWorkCapacity = libhoney.DefaultPendingWorkCapacity
	}
	if config.Client == nil {
		var tx transmission.Sender
		if config.STDOUT == true {
			fmt.Println(
				warningColor,
				`WARNING: Writing to STDOUT in a production environment is dangerous and can cause issues.`)
			tx = &transmission.WriterSender{}
		}
		if config.Mute == true {
			tx = &transmission.DiscardSender{}
		}
		if tx == nil {
			tx = &transmission.Honeycomb{
				MaxBatchSize:         config.MaxBatchSize,
				BatchTimeout:         config.BatchTimeout,
				MaxConcurrentBatches: config.MaxConcurrentBatches,
				PendingWorkCapacity:  config.PendingWorkCapacity,
				UserAgentAddition:    userAgentAddition,
			}
		}
		clientConfig := libhoney.ClientConfig{
			APIKey:       config.WriteKey,
			Dataset:      config.Dataset,
			Transmission: tx,
		}
		if config.APIHost != "" {
			clientConfig.APIHost = config.APIHost
		}
		if config.Debug {
			clientConfig.Logger = &libhoney.DefaultLogger{}
		}
		c, _ := libhoney.NewClient(clientConfig)
		client.Set(c)
	} else {
		client.Set(config.Client)
	}

	// add a bunch of fields
	client.AddField("meta.beeline_version", version)
	if config.ServiceName != "" {
		// shouldn't be empty, but just in case
		client.AddField("service_name", strings.TrimSpace(config.ServiceName))
		client.AddField("service.name", strings.TrimSpace(config.ServiceName))
	}
	if hostname, err := os.Hostname(); err == nil {
		client.AddField("meta.local_hostname", hostname)
	}

	if config.Debug {
		// TODO add more debugging than just the responses queue
		go readResponses(client.TxResponses())
	}

	// Use the sampler hook if it's defined, otherwise a deterministic sampler
	if config.SamplerHook != nil {
		trace.GlobalConfig.SamplerHook = config.SamplerHook
	} else {
		// configure and set a global sampler so sending traces can use it
		// without threading it through
		sampler, err := sample.NewDeterministicSampler(config.SampleRate)
		if err == nil {
			sample.GlobalSampler = sampler
		}
	}

	if config.PresendHook != nil {
		trace.GlobalConfig.PresendHook = config.PresendHook
	}
	// if classic, propagate by default
	if IsClassicKey(config) {
		propagation.GlobalConfig.PropagateDataset = true
	} else {
		// if non-classic, don't propagate by default
		propagation.GlobalConfig.PropagateDataset = false
	}
	trace.GlobalConfig.PprofTagging = config.PprofTagging
	return
}

// Flush sends any pending events to Honeycomb. This is optional; events will be
// flushed on a timer otherwise. It is useful to flush before AWS Lambda
// functions finish to ensure events get sent before AWS freezes the function.
// Flush implicitly ends all currently active spans.
func Flush(ctx context.Context) {
	tr := trace.GetTraceFromContext(ctx)
	if tr != nil {
		tr.Send()
	}
	client.Flush()
}

// Close shuts down the beeline. Closing does not send any pending traces but
// does flush any pending libhoney events and blocks until they have been sent.
// It is optional to close the beeline, and prohibited to try and send an event
// after the beeline has been closed.
func Close() {
	client.Close()
}

// AddField allows you to add a single field to an event anywhere downstream of
// an instrumented request. After adding the appropriate middleware or wrapping
// a Handler, feel free to call AddField freely within your code. Pass it the
// context from the request (`r.Context()`) and the key and value you wish to
// add.This function is good for span-level data, eg timers or the arguments to
// a specific function call, etc. Fields added here are prefixed with `app.`
//
// Errors are treated as a special case for convenience: if `val` is of type
// `error` then the key is set to the error's message in the span.
func AddField(ctx context.Context, key string, val interface{}) {
	span := trace.GetSpanFromContext(ctx)
	if span != nil {
		if val != nil {
			namespacedKey := fmt.Sprintf("app.%s", key)
			if valErr, ok := val.(error); ok {
				// treat errors specially because it's a pain to have to
				// remember to stringify them
				span.AddField(namespacedKey, valErr.Error())
			} else {
				span.AddField(namespacedKey, val)
			}
		}
	}
}

// AddFieldToTrace adds the field to both the currently active span and all
// other spans involved in this trace that occur within this process.
// Additionally, these fields are packaged up and passed along to downstream
// processes if they are also using a beeline. This function is good for adding
// context that is better scoped to the request than this specific unit of work,
// eg user IDs, globally relevant feature flags, errors, etc. Fields added here
// are prefixed with `app.`
func AddFieldToTrace(ctx context.Context, key string, val interface{}) {
	namespacedKey := fmt.Sprintf("app.%s", key)
	tr := trace.GetTraceFromContext(ctx)
	if tr != nil {
		tr.AddField(namespacedKey, val)
	}
}

// StartSpan lets you start a new span as a child of an already instrumented
// handler. If there isn't an existing wrapped handler in the context when this
// is called, it will start a new trace. Spans automatically get a `duration_ms`
// field when they are ended; you should not explicitly set the duration. The
// name argument will be the primary way the span is identified in the trace
// view within Honeycomb. You get back a fresh context with the new span in it
// as well as the actual span that was just created. You should call
// `span.Send()` when the span should be sent (often in a defer immediately
// after creation). You should pass the returned context downstream.
func StartSpan(ctx context.Context, name string) (context.Context, *trace.Span) {
	span := trace.GetSpanFromContext(ctx)
	var newSpan *trace.Span
	if span != nil {
		ctx, newSpan = span.CreateChild(ctx)
	} else {
		// there is no trace active; we should make one, but use the root span
		// as the "new" span instead of creating a child of this mostly empty
		// span
		ctx, _ = trace.NewTrace(ctx, nil)
		newSpan = trace.GetSpanFromContext(ctx)
	}
	newSpan.AddField("name", name)
	return ctx, newSpan
}

// readResponses pulls from the response queue and spits them to STDOUT for
// debugging
func readResponses(responses chan transmission.Response) {
	for r := range responses {
		var metadata string
		if r.Metadata != nil {
			metadata = fmt.Sprintf("%s", r.Metadata)
		}
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			message := "Successfully sent event to Honeycomb"
			if metadata != "" {
				message += fmt.Sprintf(": %s", metadata)
			}
			fmt.Printf("%s\n", message)
		} else if r.StatusCode == http.StatusUnauthorized {
			fmt.Printf("Error sending event to honeycomb! The APIKey was rejected, please verify your APIKey. %s", metadata)
		} else {
			fmt.Printf("Error sending event to Honeycomb! %s had code %d, err %v and response body %s \n",
				metadata, r.StatusCode, r.Err, r.Body)
		}
	}
}
