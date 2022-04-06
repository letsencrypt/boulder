package notmain

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/akamai"
	"github.com/letsencrypt/boulder/akamai/proto"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/test"
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

func TestAkamaiPurgerQueue(t *testing.T) {
	ap := &akamaiPurger{
		maxQueueSize: 250,
		client:       &akamai.CachePurgeClient{},
		log:          blog.NewMock(),
	}

	// Add 250 entries to fill the queue.
	for i := 0; i < 250; i++ {
		req := proto.PurgeRequest{Urls: []string{fmt.Sprintf("http://test.com/%d", i)}}
		_, err := ap.Purge(context.Background(), &req)
		test.AssertNotError(t, err, fmt.Sprintf("Purge failed for entry %d.", i))
	}

	// Add another entry to the queue and call purge.
	req := proto.PurgeRequest{Urls: []string{"http://test.com/251"}}
	_, err := ap.Purge(context.Background(), &req)
	test.AssertNotError(t, err, "Purge failed.")

	// Verify that the queue is full.
	test.AssertEquals(t, len(ap.toPurge), 250)

	// Verify that the first entry in the queue is the one we just added.
	test.AssertEquals(t, ap.toPurge[0][0], "http://test.com/251")

	// Verify that the last entry in the queue is the second entry we added.
	test.AssertEquals(t, ap.toPurge[249][0], "http://test.com/1")
}
