package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/honeycombio/beeline-go/client"
	"github.com/honeycombio/beeline-go/propagation"
	"github.com/honeycombio/beeline-go/sample"
	libhoney "github.com/honeycombio/libhoney-go"
)

const (
	traceIDLengthBytes = 16
	spanIDLengthBytes  = 8
)

var GlobalConfig Config

type Config struct {
	// SamplerHook is a function to manage sampling on this trace. See the docs
	// for `beeline.Config` for a full description.
	SamplerHook func(map[string]interface{}) (bool, int)
	// PresendHook is a function to mutate spans just before they are sent to
	// Honeycomb. See the docs for `beeline.Config` for a full description.
	PresendHook func(map[string]interface{})

	// PprofTagging controls whether span IDs should be propagated to pprof.
	PprofTagging bool
}

// Trace holds some trace level state and the root of the span tree that will be
// the entire in-process trace. Traces are sent to Honeycomb when the root span
// is sent. You can send a trace manually, and that will cause all
// synchronous  spans in the trace to be sent and sent. Asynchronous spans
// must still be sent on their own
type Trace struct {
	builder          *libhoney.Builder
	traceID          string
	parentID         string
	rollupFields     map[string]float64
	rollupLock       sync.Mutex
	rootSpan         *Span
	tlfLock          sync.RWMutex
	traceLevelFields map[string]interface{}
}

// getNewID generates a lowercase hex encoded string with the specified number
// of bytes. It is used for ID generation for traces and spans.
func getNewID(length uint16) string {
	id := make([]byte, length)
	// rand.Seed is called in libhoney's init, so this is sure to have well-seeded random content.
	_, _ = rand.Read(id)
	return hex.EncodeToString(id)
}

// NewTraceFromPropagationContext creates a brand new trace. prop is optional, and if included,
// should be populated with data from a trace context header.
//
// Deprecated: use NewTrace instead.
func NewTraceFromPropagationContext(ctx context.Context, prop *propagation.PropagationContext) (context.Context, *Trace) {
	trace := &Trace{
		builder:          client.NewBuilder(),
		rollupFields:     make(map[string]float64),
		traceLevelFields: make(map[string]interface{}),
	}

	if prop != nil {
		trace.traceID = prop.TraceID
		trace.parentID = prop.ParentID
		for k, v := range prop.TraceContext {
			trace.traceLevelFields[k] = v
		}
		if prop.Dataset != "" {
			trace.builder.Dataset = prop.Dataset
		}
	}

	if trace.traceID == "" {
		trace.traceID = getNewID(traceIDLengthBytes)
	}

	rootSpan := newSpan()
	rootSpan.isRoot = true
	if trace.parentID != "" {
		rootSpan.parentID = trace.parentID
	}
	rootSpan.ev = trace.builder.NewEvent()
	rootSpan.trace = trace
	trace.rootSpan = rootSpan

	// put trace and root span in context
	ctx = PutTraceInContext(ctx, trace)
	ctx = PutSpanInContext(ctx, rootSpan)
	return ctx, trace
}

// NewTraceFromSerializedHeaders creates a brand new trace. serializedHeaders is optional, and if
// included, should be the header as written by trace.SerializeHeaders(). When
// not starting from an upstream trace, pass the empty string here.
//
// Deprecated: use NewTrace instead.
func NewTraceFromSerializedHeaders(ctx context.Context, serializedHeaders string) (context.Context, *Trace) {
	var prop *propagation.PropagationContext
	if serializedHeaders != "" {
		prop, _ = propagation.UnmarshalHoneycombTraceContext(serializedHeaders)
	}
	return NewTraceFromPropagationContext(ctx, prop)
}

// NewTrace creates a new trace. prop is optional, and if included,
// should be populated with data from a trace context header.
func NewTrace(ctx context.Context, prop *propagation.PropagationContext) (context.Context, *Trace) {
	return NewTraceFromPropagationContext(ctx, prop)
}

// AddField adds a field to the trace. Every span in the trace will have this
// field added to it. These fields are also passed along to downstream services.
// It is useful to add fields here that pertain to the entire trace, to aid in
// filtering spans at many different areas of the trace together.
func (t *Trace) AddField(key string, val interface{}) {
	t.tlfLock.Lock()
	defer t.tlfLock.Unlock()
	if t.traceLevelFields != nil {
		t.traceLevelFields[key] = val
	}
}

// serializeHeaders returns the trace ID, given span ID as parent ID, and an
// encoded form of all trace level fields. This serialized header is intended
// to be put in an HTTP (or other protocol) header to transmit to downstream
// services so they may start a new trace that will be connected to this trace.
// The serialized form may be passed to NewTrace() in order to create a new
// trace that will be connected to this trace.
func (t *Trace) serializeHeaders(spanID string) string {
	prop := t.propagationContext()
	prop.ParentID = spanID
	return propagation.MarshalHoneycombTraceContext(prop)
}

// propagationContext returns a partially populated propagation context. It only
// has the fields that come from the trace level - after getting the returned
// object the caller must still fill in the span ID in order to fully populate
// the PropagationContext struct for use creating serialized headers.
func (t *Trace) propagationContext() *propagation.PropagationContext {
	// make a copy of the trace level fields map since we can't lock our
	// returned value to protect it
	t.tlfLock.Lock()
	defer t.tlfLock.Unlock()
	localTLF := map[string]interface{}{}
	for k, v := range t.traceLevelFields {
		localTLF[k] = v
	}
	return &propagation.PropagationContext{
		TraceID:      t.traceID,
		Dataset:      t.builder.Dataset,
		TraceContext: localTLF,
		TraceFlags:   propagation.FlagsSampled, // TODO: set the sampled flag based on sampler decision
	}
}

// addRollupField is here to let a span contribute a field to the trace while
// keeping the trace's locks private.
func (t *Trace) addRollupField(key string, val float64) {
	t.rollupLock.Lock()
	defer t.rollupLock.Unlock()
	if t.rollupFields != nil {
		t.rollupFields[key] += val
	}
}

// getTraceLevelFields is here to let a span retrieve trace level fields to add
// them to itself just before sending while keeping the trace's locks around
// that field private.
func (t *Trace) getTraceLevelFields() map[string]interface{} {
	t.tlfLock.Lock()
	defer t.tlfLock.Unlock()
	// return a copy of trace level fields
	retVals := make(map[string]interface{})
	for k, v := range t.traceLevelFields {
		retVals[k] = v
	}
	return retVals
}

func (t *Trace) getRollupFields() map[string]interface{} {
	t.rollupLock.Lock()
	defer t.rollupLock.Unlock()
	rollupFields := make(map[string]interface{})
	for k, v := range t.rollupFields {
		rollupFields[k] = v
	}
	return rollupFields
}

// GetRootSpan returns the root of the in-process trace. Sending the root span
// will send the entire trace to Honeycomb. From the root span you can walk the
// entire span tree using GetChildren (and recursively calling GetChildren on
// each child).
func (t *Trace) GetRootSpan() *Span {
	return t.rootSpan
}

// GetTraceID returns the ID of the trace
func (t *Trace) GetTraceID() string {
	return t.traceID
}

// GetParentID returns the ID of the parent trace
func (t *Trace) GetParentID() string {
	return t.parentID
}

// Send will finish and send all the synchronous spans in the trace to Honeycomb
func (t *Trace) Send() {
	rs := t.rootSpan
	if !rs.isSent {
		rs.Send()
		// sending the span will also send all its children
	}
}

// Span represents a specific task or portion of an application. It has a time
// and duration, and is linked to parent and children.
type Span struct {
	isAsync      bool
	isSent       bool
	isRoot       bool
	children     []*Span
	childrenLock sync.Mutex
	ev           *libhoney.Event
	spanID       string
	parentID     string
	parent       *Span
	rollupFields map[string]float64
	rollupLock   sync.Mutex
	started      time.Time
	trace        *Trace
	eventLock    sync.Mutex
	sendLock     sync.RWMutex
	oldCtx       *context.Context
}

// newSpan takes care of *some* of the initialization necessary to create a new
// span. IMPORTANT it is not all of the initialization! It does *not* set parent
// ID or assign the pointer to the trace that contains this span. See existing
// uses of this function to get an example of the other things necessary to
// create a well formed span.
func newSpan() *Span {
	return &Span{
		spanID:  getNewID(spanIDLengthBytes),
		started: time.Now(),
	}
}

// AddField adds a key/value pair to this span
//
// Errors are treated as a special case for convenience: if `val` is of type
// `error` then the key is set to the error's message in the span.
func (s *Span) AddField(key string, val interface{}) {
	// The call to event's AddField is protected by a lock, but this is not always sufficient
	// See send for why this lock exists
	s.eventLock.Lock()
	defer s.eventLock.Unlock()
	if s.ev != nil {
		if err, ok := val.(error); ok {
			s.ev.AddField(key, err.Error())
		} else {
			s.ev.AddField(key, val)
		}
	}
}

// AddRollupField adds a key/value pair to this span. If it is called repeatedly
// on the same span, the values will be summed together.  Additionally, this
// field will be summed across all spans and added to the trace as a total. It
// is especially useful for doing things like adding the duration spent talking
// to a specific external service - eg database time. The root span will then
// get a field that represents the total time spent talking to the database from
// all of the spans that are part of the trace.
func (s *Span) AddRollupField(key string, val float64) {
	if s.trace != nil {
		s.trace.addRollupField(key, val)
	}
	s.rollupLock.Lock()
	defer s.rollupLock.Unlock()
	if s.rollupFields == nil {
		s.rollupFields = make(map[string]float64)
	}
	if s.rollupFields != nil {
		s.rollupFields[key] += val
	}
}

// AddTraceField adds a key/value pair to this span and all others involved in
// this trace. These fields are also passed along to downstream services. This
// method is functionally identical to `Trace.AddField()`.
func (s *Span) AddTraceField(key string, val interface{}) {
	// these get added to this span when it gets sent, so don't bother adding
	// them here
	if s.trace != nil {
		s.trace.AddField(key, val)
	}
}

// Send marks a span complete. It does some accounting and then dispatches the
// span to Honeycomb. Sending a span also triggers sending all synchronous
// child spans - in other words, if any synchronous child span has not yet been
// sent, sending the parent will finish and send the children as well.
func (s *Span) Send() {
	s.sendLock.Lock()
	defer s.sendLock.Unlock()
	// don't send already sent spans
	if s.isSent {
		return
	}

	s.sendLocked()
}

func (s *Span) sendByParent() {
	s.sendLock.Lock()
	defer s.sendLock.Unlock()
	// don't send already sent spans
	if s.isSent {
		return
	}

	s.AddField("meta.sent_by_parent", true)
	s.sendLocked()
}

func (s *Span) sendLocked() {
	if s.ev == nil {
		return
	}
	// finish the timer for this span
	if !s.started.IsZero() {
		dur := float64(time.Since(s.started)) / float64(time.Millisecond)
		s.AddField("duration_ms", dur)
	}
	// set trace IDs for this span
	s.ev.AddField("trace.trace_id", s.trace.traceID)
	if s.parentID != "" {
		s.AddField("trace.parent_id", s.parentID)
	}
	s.ev.AddField("trace.span_id", s.spanID)
	// add this span's rollup fields to the event
	s.rollupLock.Lock()
	for k, v := range s.rollupFields {
		s.AddField(k, v)
	}
	s.rollupLock.Unlock()

	s.childrenLock.Lock()
	var childrenToSend []*Span
	if len(s.children) > 0 {
		childrenToSend = make([]*Span, 0, len(s.children))
		for _, child := range s.children {
			if !child.IsAsync() {
				// queue children up to be sent. We'd deadlock if we actually sent the
				// child here.
				childrenToSend = append(childrenToSend, child)
			}
		}
	}
	s.childrenLock.Unlock()

	for _, child := range childrenToSend {
		child.sendByParent()
	}

	s.send()
	s.isSent = true

	// Remove this span from its parent's children list so that it can be GC'd
	if s.parent != nil {
		s.parent.removeChildSpan(s)
	}

	// Restore pprof labels from before this span was created, if any were saved.
	if s.oldCtx != nil {
		pprof.SetGoroutineLabels(*s.oldCtx)
	}
}

// IsAsync reveals whether the span is asynchronous (true) or synchronous (false).
func (s *Span) IsAsync() bool {
	return s.isAsync
}

// GetChildren returns a list of all child spans (both synchronous and
// asynchronous).
func (s *Span) GetChildren() []*Span {
	return s.children
}

// Get Parent returns this span's parent.
func (s *Span) GetParent() *Span {
	return s.parent
}

// GetSpanID returns the ID of the span
func (t *Span) GetSpanID() string {
	return t.spanID
}

// GetParentID returns the ID of the parent span
func (t *Span) GetParentID() string {
	return t.parentID
}

// GetTrace returns a pointer to the trace enclosing the span
func (t *Span) GetTrace() *Trace {
	return t.trace
}

// CreateAsyncChild creates a child of the current span that is expected to
// outlive the current span (and trace). Async spans are not automatically sent
// when their parent finishes, but are otherwise identical to synchronous spans.
func (s *Span) CreateAsyncChild(ctx context.Context) (context.Context, *Span) {
	return s.createChildSpan(ctx, true)
}

// Span creates a synchronous child of the current span. Spans must finish
// before their parents.
func (s *Span) CreateChild(ctx context.Context) (context.Context, *Span) {
	return s.createChildSpan(ctx, false)
}

// SerializeHeaders returns the trace ID, current span ID as parent ID, and an
// encoded form of all trace level fields. This serialized header is intended to
// be put in an HTTP (or other protocol) header to transmit to downstream
// services so they may start a new trace that will be connected to this trace.
// The serialized form may be passed to NewTrace() in order to create a new
// trace that will be connected to this trace.
func (s *Span) SerializeHeaders() string {
	return s.trace.serializeHeaders(s.spanID)
}

// removeChildSpan remove a child which has been sent. It is intended to be
// called after a child of this span has been sent.
func (s *Span) removeChildSpan(sentSpan *Span) {
	s.childrenLock.Lock()
	defer s.childrenLock.Unlock()
	var index *int
	for i, child := range s.children {
		i := i
		if child == sentSpan {
			index = &i
		}
	}
	if index != nil {
		s.children = append(s.children[:*index], s.children[*index+1:]...)
	}
}

// send gets all the trace level fields and does pre-send hooks, then sends the
// span.
func (s *Span) send() {
	// add all the trace level fields to the event as late as possible - when
	// the trace is all getting sent
	for k, v := range s.trace.getTraceLevelFields() {
		s.AddField(k, v)
	}

	s.childrenLock.Lock()
	// classify span type
	var spanType string
	switch {
	case s.isRoot:
		if s.parentID == "" {
			spanType = "root"
		} else {
			spanType = "subroot"
		}
	case s.isAsync:
		spanType = "async"
	case len(s.children) == 0:
		spanType = "leaf"
	default:
		spanType = "mid"
	}
	s.childrenLock.Unlock()
	s.AddField("meta.span_type", spanType)

	if s.isRoot {
		// add the trace's rollup fields to the root span
		for k, v := range s.trace.getRollupFields() {
			s.AddField("rollup."+k, v)
		}
	}

	// Because we hand a raw map over to the Sampler and Presend hooks, it's
	// possible for the user to modify/iterate over the map in these hooks and
	// still modify the event somewhere else with AddField. We lock here to
	// prevent this from causing an unnecessary panic.
	s.eventLock.Lock()
	defer s.eventLock.Unlock()
	// run hooks
	var shouldKeep = true
	if GlobalConfig.SamplerHook != nil {
		var sampleRate int
		shouldKeep, sampleRate = GlobalConfig.SamplerHook(s.ev.Fields())
		s.ev.SampleRate = uint(sampleRate)
	} else {
		// use the default sampler
		if sample.GlobalSampler != nil {
			shouldKeep = sample.GlobalSampler.Sample(s.trace.traceID)
			s.ev.SampleRate = uint(sample.GlobalSampler.GetSampleRate())
		}
	}
	if shouldKeep {
		if GlobalConfig.PresendHook != nil {
			// munge all the fields
			GlobalConfig.PresendHook(s.ev.Fields())
		}
		s.ev.SendPresampled()
	}
}

func (s *Span) createChildSpan(ctx context.Context, async bool) (context.Context, *Span) {
	newSpan := newSpan()
	newSpan.parent = s
	newSpan.parentID = s.spanID
	newSpan.trace = s.trace
	newSpan.ev = s.trace.builder.NewEvent()
	newSpan.isAsync = async
	s.childrenLock.Lock()
	s.children = append(s.children, newSpan)
	s.childrenLock.Unlock()
	ctx = PutSpanInContext(ctx, newSpan)
	return ctx, newSpan
}

// PropagationContext creates and returns a new propagation.PropagationContext using the
// information in the current span.
func (s *Span) PropagationContext() *propagation.PropagationContext {
	prop := s.trace.propagationContext()
	prop.ParentID = s.spanID
	return prop
}
