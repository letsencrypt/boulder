package notmain

import (
	"testing"
	"time"
)

func TestThroughput_validate(t *testing.T) {
	type fields struct {
		ResponsesPerBatch int
		PurgeBatchEvery   time.Duration
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
				ResponsesPerBatch: DeprecatedResponsesPerBatch,
				PurgeBatchEvery:   10 * time.Second},
			false,
		},
		{"optimized defaults, should succeed",
			fields{
				ResponsesPerBatch: defaultResponsesPerBatch,
				PurgeBatchEvery:   defaultPurgeBatchEvery},
			false,
		},
		{"2ms faster than optimized defaults, should succeed",
			fields{
				ResponsesPerBatch: defaultResponsesPerBatch,
				PurgeBatchEvery:   defaultPurgeBatchEvery + 2*time.Millisecond},
			false,
		},
		{"exceeds URLs per second by 4 URLs",
			fields{
				ResponsesPerBatch: defaultResponsesPerBatch,
				PurgeBatchEvery:   29 * time.Millisecond},
			true,
		},
		{"exceeds bytes per second by 20 bytes",
			fields{
				ResponsesPerBatch: 125,
				PurgeBatchEvery:   1 * time.Second},
			true,
		},
		{"exceeds requests per second by 1 request",
			fields{
				ResponsesPerBatch: 1,
				PurgeBatchEvery:   19999 * time.Microsecond},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Throughput{
				ResponsesPerBatch: tt.fields.ResponsesPerBatch,
			}
			tr.PurgeBatchEvery.Duration = tt.fields.PurgeBatchEvery
			if err := tr.validate(); (err != nil) != tt.wantErr {
				t.Errorf("Throughput.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
