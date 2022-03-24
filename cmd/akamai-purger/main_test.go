package notmain

import (
	"testing"
	"time"
)

func TestThroughput_validate(t *testing.T) {
	type fields struct {
		QueueEntriesPerBatch int
		PurgeBatchInterval   time.Duration
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		// TODO(#6003) This test case can be removed entirely. It was added to
		// prove that this change met our deployability guidelines. The existing
		// test/config couldn't modified to reflect production without adding 10
		// seconds of wait to verify_akamai_purge() in test/helpers.py.
		{"production configuration prior to this change",
			fields{
				QueueEntriesPerBatch: DeprecatedQueueEntriesPerBatch,
				PurgeBatchInterval:   10 * time.Second},
			false,
		},
		{"optimized defaults, should succeed",
			fields{
				QueueEntriesPerBatch: defaultQueueEntriesPerBatch,
				PurgeBatchInterval:   defaultPurgeBatchInterval},
			false,
		},
		{"2ms faster than optimized defaults, should succeed",
			fields{
				QueueEntriesPerBatch: defaultQueueEntriesPerBatch,
				PurgeBatchInterval:   defaultPurgeBatchInterval + 2*time.Millisecond},
			false,
		},
		{"exceeds URLs per second by 4 URLs",
			fields{
				QueueEntriesPerBatch: defaultQueueEntriesPerBatch,
				PurgeBatchInterval:   29 * time.Millisecond},
			true,
		},
		{"exceeds bytes per second by 20 bytes",
			fields{
				QueueEntriesPerBatch: 125,
				PurgeBatchInterval:   1 * time.Second},
			true,
		},
		{"exceeds requests per second by 1 request",
			fields{
				QueueEntriesPerBatch: 1,
				PurgeBatchInterval:   19999 * time.Microsecond},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Throughput{
				QueueEntriesPerBatch: tt.fields.QueueEntriesPerBatch,
			}
			tr.PurgeBatchInterval.Duration = tt.fields.PurgeBatchInterval
			if err := tr.validate(); (err != nil) != tt.wantErr {
				t.Errorf("Throughput.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
