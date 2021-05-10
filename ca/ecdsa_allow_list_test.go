package ca

import (
	"reflect"
	"testing"

	"github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/reloader"
	"github.com/prometheus/client_golang/prometheus"
)

func TestNewECDSAAllowListFromFile(t *testing.T) {
	type args struct {
		filename string
		reloader *reloader.Reloader
		logger   log.Logger
		metric   *prometheus.GaugeVec
	}
	tests := []struct {
		name          string
		args          args
		wantAllowList *ECDSAAllowList
		wantEntries   int
		wantErrBool   bool
	}{
		{
			name:          "one entry",
			args:          args{"testdata/ecdsa_allow_list.yml", nil, nil, nil},
			wantAllowList: &ECDSAAllowList{regIDsMap: map[int64]bool{1337: true}, reloader: nil, logger: nil, statusGauge: nil},
			wantEntries:   1,
			wantErrBool:   false,
		},
		{
			name:          "should error due to no file",
			args:          args{"testdata/ecdsa_allow_list_no_exist.yml", nil, nil, nil},
			wantAllowList: nil,
			wantEntries:   0,
			wantErrBool:   true,
		},
		{
			name:          "should error due to malformed YAML",
			args:          args{"testdata/ecdsa_allow_list_malformed.yml", nil, nil, nil},
			wantAllowList: nil,
			wantEntries:   0,
			wantErrBool:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := NewECDSAAllowListFromFile(tt.args.filename, tt.args.reloader, tt.args.logger, tt.args.metric)

			if (err != nil) != tt.wantErrBool {
				t.Errorf("NewECDSAAllowListFromFile() error = %v, wantErr %v", err, tt.wantErrBool)
				t.Error(got, got1, err)
				return
			}
			if !reflect.DeepEqual(got, tt.wantAllowList) {
				t.Errorf("NewECDSAAllowListFromFile() got = %v, want %v", got, tt.wantAllowList)
			}
			if got1 != tt.wantEntries {
				t.Errorf("NewECDSAAllowListFromFile() got1 = %v, want %v", got1, tt.wantEntries)
			}
		})
	}
}

func TestNewECDSAAllowListFromConfig(t *testing.T) {
	type args struct {
		regIDs []int64
	}
	tests := []struct {
		name          string
		args          args
		wantAllowList *ECDSAAllowList
		wantEntries   int
		wantErrBool   bool
	}{
		{
			name:          "one entry",
			args:          args{[]int64{1337}},
			wantAllowList: &ECDSAAllowList{regIDsMap: map[int64]bool{1337: true}, reloader: nil, logger: nil, statusGauge: nil},
			wantEntries:   1,
			wantErrBool:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := NewECDSAAllowListFromConfig(tt.args.regIDs)
			if (err != nil) != tt.wantErrBool {
				t.Errorf("NewECDSAAllowListFromConfig() error = %v, wantErr %v", err, tt.wantErrBool)
				return
			}
			if !reflect.DeepEqual(got, tt.wantAllowList) {
				t.Errorf("NewECDSAAllowListFromConfig() got = %v, want %v", got, tt.wantAllowList)
			}
			if got1 != tt.wantEntries {
				t.Errorf("NewECDSAAllowListFromConfig() got1 = %v, want %v", got1, tt.wantEntries)
			}
		})
	}
}
