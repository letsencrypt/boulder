package tiles

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestPath(t *testing.T) {
	type testCase struct {
		name                string
		tileIndex, treeSize int64
		want                string
	}

	testCases := []testCase{
		{"zero one", 0, 1, "tile/entries/000.p/1"},
		{"zero 255", 0, 255, "tile/entries/000.p/255"},
		{"zero 256", 0, 256, "tile/entries/000"},
		{"ten 1000", 10, 1000, "tile/entries/010"},
		{"example", 1234067, 99999999, "tile/entries/x001/x234/067"},
		{"example partial", 1234067, 1234067*256 + 6, "tile/entries/x001/x234/067.p/6"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := tilePath(tc.tileIndex, tc.treeSize)
			if p != tc.want {
				t.Errorf("tilePath(%d, %d): got %s, want %s",
					tc.tileIndex, tc.treeSize, p, tc.want)
			}
		})
	}
}

func TestPartialWidth(t *testing.T) {
	type testCase struct {
		tileIndex, treeSize int64
		want                int
	}
	testCases := []testCase{
		{0, 0, 0},
		{0, 1, 1},
		{0, 2, 2},
		{0, 3, 3},
		{0, 255, 255},
		{0, 256, 0},
		{1, 256 + 0, 0},
		{1, 256 + 1, 1},
		{1, 256 + 2, 2},
		{1, 256 + 3, 3},
		{1, 256 + 255, 255},
		{1, 256 + 256, 0},
		{2, 2*256 + 0, 0},
		{2, 2*256 + 1, 1},
		{2, 2*256 + 2, 2},
		{2, 2*256 + 3, 3},
		{2, 2*256 + 255, 255},
		{2, 2*256 + 256, 0},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%d,%d", tc.tileIndex, tc.treeSize), func(t *testing.T) {
			result := partialWidth(tc.tileIndex, tc.treeSize)
			if result != tc.want {
				t.Errorf("partialWidth(%d, %d)=%d, want %d",
					tc.tileIndex, tc.treeSize, result, tc.want)
			}
		})
	}
}

type fakeS3 struct {
	objects map[string][]byte
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: make(map[string][]byte)}
}

func (f *fakeS3) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return nil, nil
}
func (f *fakeS3) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, nil
}
func (f *fakeS3) Bucket() string {
	return "fakebucket"
}

func TestGetEntries(t *testing.T) {
	fs3 := newFakeS3()

	_, _, err := GetEntries(t.Context(), fs3, 0, 0)
	if err == nil {
		t.Errorf("GetEntries(0,0): got nil error, want error")
	}
}
