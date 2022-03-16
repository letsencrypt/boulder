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
		{"deployability defaults",
			fields{
				ResponsesPerBatch: 33,
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
				PurgeBatchEvery:   30 * time.Millisecond},
			false,
		},
		{"3ms faster than optimized defaults, exceed by 4 URLs",
			fields{
				ResponsesPerBatch: defaultResponsesPerBatch,
				PurgeBatchEvery:   29 * time.Millisecond},
			true,
		},
		{"exceed by 20 bytes",
			fields{
				ResponsesPerBatch: 125,
				PurgeBatchEvery:   1 * time.Second},
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
