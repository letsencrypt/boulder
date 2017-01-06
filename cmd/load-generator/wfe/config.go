package wfe

import "time"

type Config struct {
	// Execution plan parameters
	Plan struct {
		Actions   []string      // things to do
		Rate      int           // requests / s
		RateDelta int           // requests / s^2
		MaxRate   int           // XXX: is this needed?
		Runtime   time.Duration // how long to run for
	}
	ExternalState string   // path to file to load/save registrations etc to/from
	DontSaveState bool     // don't save changes to external state
	APIBase       string   // ACME API address to send requests to
	DomainBase    string   // base domain name to create authorizations for
	ChallTypes    []string // which challenges to complete, empty means use all
	HTTPOneAddr   string   // address to listen for http-01 validation requests on
	TLSOneAddr    string   // address to listen for tls-sni-01 validation requests on
	RealIP        string   // value of the Real-IP header to use when bypassing CDN
	RegKeySize    int      // size of the key to use in registrations
	CertKeySize   int      // size of the key to use when creating CSRs
	RegEmail      string   // email to use in registrations
	Results       string   // path to save metrics to
	MaxRegs       int      // maximum number of registrations to create
}
