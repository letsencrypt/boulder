// Package unbound implements a wrapper for libunbound(3).
// Unbound is a DNSSEC aware resolver, see https://unbound.net/
// for more information. It's up to the caller to configure
// Unbound with trust anchors. With these anchors a DNSSEC
// answer can be validated.
//
// The method's documentation can be found in libunbound(3).
// The names of the methods are in sync with the
// names used in unbound, but the underscores are removed and they
// are in camel-case, e.g. ub_ctx_resolv_conf becomes u.ResolvConf.
// Except for ub_ctx_create() and ub_ctx_delete(),
// which become: New() and Destroy() to be more in line with the standard
// Go practice.
//
// Basic use pattern:
//	u := unbound.New()
//	defer u.Destroy()
//	u.ResolvConf("/etc/resolv.conf")
//	u.AddTaFile("trustanchor")
//	r, e := u.Resolve("miek.nl.", dns.TypeA, dns.ClassINET)
//
// The asynchronous functions are implemented using goroutines. This
// means the following functions are not useful in Go and therefor
// not implemented: ub_fd, ub_wait, ub_poll, ub_process and ub_cancel.
//
// Unbound's ub_result (named Result in the package) has been modified.
// An extra field has been added, 'Rr', which is a []dns.RR.
//
// The Lookup* functions of the net package are re-implemented in this package.
package unbound

/*
#cgo LDFLAGS: -lunbound
#include <stdlib.h>
#include <stdio.h>
#include <unbound.h>
#define offsetof(type, member)  __builtin_offsetof (type, member)

int    array_elem_int(int *l, int i)    { return l[i]; }
char * array_elem_char(char **l, int i) { if (l == NULL) return NULL; return l[i]; }
char * new_char_pointer()               { char *p = NULL; return p; }
struct ub_result *new_ub_result() {
	struct ub_result *r;
	r = calloc(sizeof(struct ub_result), 1);
	return r;
}
int    ub_ttl(struct ub_result *r) {
	int *p;
	// Go to why_bogus add the pointer and then we will find the ttl, hopefully.
	p = (int*) ((char*)r + offsetof(struct ub_result, why_bogus) + sizeof(char*));
	return (int)*p;
}
*/
import "C"

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

type Unbound struct {
	ctx     *C.struct_ub_ctx
	version [3]int
}

// Results is Unbound's ub_result adapted for Go.
type Result struct {
	Qname        string        // Text string, original question
	Qtype        uint16        // Type code asked for
	Qclass       uint16        // Class code asked for
	Data         [][]byte      // Slice of rdata items formed from the reply
	Rr           []dns.RR      // The RR encoded from Data, Qclass, Qtype, Qname and Ttl (not in Unbound)
	CanonName    string        // Canonical name of result
	Rcode        int           // Additional error code in case of no data
	AnswerPacket *dns.Msg      // Full answer packet
	HaveData     bool          // True if there is data
	NxDomain     bool          // True if the name does not exist
	Secure       bool          // True if the result is secure
	Bogus        bool          // True if a security failure happened
	WhyBogus     string        // String with error when bogus
	Ttl          uint32        // TTL for the result in seconds (0 for unbound versions < 1.4.20)
	Rtt          time.Duration // Time the query took (not in Unbound)
}

// UnboundError is an error returned from Unbound, it wraps both the
// return code and the error string as returned by ub_strerror.
type UnboundError struct {
	Err  string
	code int
}

// ResultError encapsulates a *Result and an error. This is used to
// communicate with unbound over a channel.
type ResultError struct {
	*Result
	Error error
}

func (e *UnboundError) Error() string {
	return e.Err
}

func newError(i int) error {
	if i == 0 {
		return nil
	}
	e := new(UnboundError)
	e.Err = errorString(i)
	e.code = i
	return e
}

func errorString(i int) string {
	return C.GoString(C.ub_strerror(C.int(i)))
}

// unbound version from 1.4.20 (inclusive) and above fill in the Tll in the result
// check if we have such a version
func (u *Unbound) haveTtlFeature() bool {
	if u.version[0] < 1 {
		return false
	}
	if u.version[1] < 4 {
		return false
	}
	if u.version[2] < 20 {
		return false
	}
	return true
}

// New wraps Unbound's ub_ctx_create.
func New() *Unbound {
	u := new(Unbound)
	u.ctx = C.ub_ctx_create()
	u.version = u.Version()
	return u
}

// Destroy wraps Unbound's ub_ctx_delete.
func (u *Unbound) Destroy() {
	C.ub_ctx_delete(u.ctx)
}

// ResolvConf wraps Unbound's ub_ctx_resolvconf.
func (u *Unbound) ResolvConf(fname string) error {
	cfname := C.CString(fname)
	defer C.free(unsafe.Pointer(cfname))
	i := C.ub_ctx_resolvconf(u.ctx, cfname)
	return newError(int(i))
}

// SetOption wraps Unbound's ub_ctx_set_option.
func (u *Unbound) SetOption(opt, val string) error {
	copt := C.CString(opt)
	defer C.free(unsafe.Pointer(copt))
	cval := C.CString(val)
	defer C.free(unsafe.Pointer(cval))
	i := C.ub_ctx_set_option(u.ctx, copt, cval)
	return newError(int(i))
}

// GetOption wraps Unbound's ub_ctx_get_option.
func (u *Unbound) GetOption(opt string) (string, error) {
	copt := C.CString(opt)
	defer C.free(unsafe.Pointer(copt))

	cval := C.new_char_pointer()
	defer C.free(unsafe.Pointer(cval))
	i := C.ub_ctx_get_option(u.ctx, C.CString(opt), &cval)
	return C.GoString(cval), newError(int(i))
}

// Config wraps Unbound's ub_ctx_config.
func (u *Unbound) Config(fname string) error {
	cfname := C.CString(fname)
	defer C.free(unsafe.Pointer(cfname))
	i := C.ub_ctx_config(u.ctx, cfname)
	return newError(int(i))
}

// SetFwd wraps Unbound's ub_ctx_set_fwd.
func (u *Unbound) SetFwd(addr string) error {
	caddr := C.CString(addr)
	defer C.free(unsafe.Pointer(caddr))
	i := C.ub_ctx_set_fwd(u.ctx, caddr)
	return newError(int(i))
}

// Hosts wraps Unbound's ub_ctx_hosts.
func (u *Unbound) Hosts(fname string) error {
	cfname := C.CString(fname)
	defer C.free(unsafe.Pointer(cfname))
	i := C.ub_ctx_hosts(u.ctx, cfname)
	return newError(int(i))
}

// Resolve wraps Unbound's ub_resolve.
func (u *Unbound) Resolve(name string, rrtype, rrclass uint16) (*Result, error) {
	name = dns.Fqdn(name)
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	res := C.new_ub_result()
	r := new(Result)
	defer C.ub_resolve_free(res)
	t := time.Now()
	i := C.ub_resolve(u.ctx, cname, C.int(rrtype), C.int(rrclass), &res)
	r.Rtt = time.Since(t)
	err := newError(int(i))
	if err != nil {
		return nil, err
	}

	r.Qname = C.GoString(res.qname)
	r.Qtype = uint16(res.qtype)
	r.Qclass = uint16(res.qclass)

	r.CanonName = C.GoString(res.canonname)
	r.Rcode = int(res.rcode)
	r.AnswerPacket = new(dns.Msg)
	r.AnswerPacket.Unpack(C.GoBytes(res.answer_packet, res.answer_len)) // Should always work
	r.HaveData = res.havedata == 1
	r.NxDomain = res.nxdomain == 1
	r.Secure = res.secure == 1
	r.Bogus = res.bogus == 1
	r.WhyBogus = C.GoString(res.why_bogus)
	if u.haveTtlFeature() {
		r.Ttl = uint32(C.ub_ttl(res))
	}

	// Re-create the RRs
	var h dns.RR_Header
	h.Name = r.Qname
	h.Rrtype = r.Qtype
	h.Class = r.Qclass
	h.Ttl = r.Ttl

	j := 0
	if r.HaveData {
		r.Data = make([][]byte, 0)
		r.Rr = make([]dns.RR, 0)
		b := C.GoBytes(unsafe.Pointer(C.array_elem_char(res.data, C.int(j))), C.array_elem_int(res.len, C.int(j)))
		for len(b) != 0 {
			// Create the RR
			h.Rdlength = uint16(len(b))
			msg := make([]byte, 20+len(h.Name)) // Long enough
			off, _ := dns.PackStruct(&h, msg, 0)
			msg = msg[:off]
			rrbuf := append(msg, b...)
			rr, _, err := dns.UnpackRR(rrbuf, 0)
			if err == nil {
				r.Rr = append(r.Rr, rr)
			}

			r.Data = append(r.Data, b)
			j++
			b = C.GoBytes(unsafe.Pointer(C.array_elem_char(res.data, C.int(j))), C.array_elem_int(res.len, C.int(j)))

		}
	}
	return r, err
}

// ResolveAsync does *not* wrap the Unbound function, instead
// it utilizes Go's goroutines and channels to implement the asynchronous behavior Unbound
// implements. As a result the function signature is different.
// The result (or an error) is returned on the channel c.
// Also the ub_cancel, ub_wait_, ub_fd, ub_process are not implemented.
func (u *Unbound) ResolveAsync(name string, rrtype, rrclass uint16, c chan *ResultError) {
	go func() {
		r, e := u.Resolve(name, rrtype, rrclass)
		c <- &ResultError{r, e}
	}()
	return
}

// AddTa wraps Unbound's ub_ctx_add_ta.
func (u *Unbound) AddTa(ta string) error {
	cta := C.CString(ta)
	i := C.ub_ctx_add_ta(u.ctx, cta)
	return newError(int(i))
}

// AddTaFile wraps Unbound's ub_ctx_add_ta_file.
func (u *Unbound) AddTaFile(fname string) error {
	cfname := C.CString(fname)
	defer C.free(unsafe.Pointer(cfname))
	i := C.ub_ctx_add_ta_file(u.ctx, cfname)
	return newError(int(i))
}

// TrustedKeys wraps Unbound's ub_ctx_trustedkeys.
func (u *Unbound) TrustedKeys(fname string) error {
	cfname := C.CString(fname)
	defer C.free(unsafe.Pointer(cfname))
	i := C.ub_ctx_trustedkeys(u.ctx, cfname)
	return newError(int(i))
}

// ZoneAdd wraps Unbound's ub_ctx_zone_add.
func (u *Unbound) ZoneAdd(zone_name, zone_type string) error {
	czone_name := C.CString(zone_name)
	defer C.free(unsafe.Pointer(czone_name))
	czone_type := C.CString(zone_type)
	defer C.free(unsafe.Pointer(czone_type))
	i := C.ub_ctx_zone_add(u.ctx, czone_name, czone_type)
	return newError(int(i))
}

// ZoneRemove wraps Unbound's ub_ctx_zone_remove.
func (u *Unbound) ZoneRemove(zone_name string) error {
	czone_name := C.CString(zone_name)
	defer C.free(unsafe.Pointer(czone_name))
	i := C.ub_ctx_zone_remove(u.ctx, czone_name)
	return newError(int(i))
}

// DataAdd wraps Unbound's ub_ctx_data_add.
func (u *Unbound) DataAdd(data string) error {
	cdata := C.CString(data)
	defer C.free(unsafe.Pointer(cdata))
	i := C.ub_ctx_data_add(u.ctx, cdata)
	return newError(int(i))
}

// DataRemove wraps Unbound's ub_ctx_data_remove.
func (u *Unbound) DataRemove(data string) error {
	cdata := C.CString(data)
	defer C.free(unsafe.Pointer(cdata))
	i := C.ub_ctx_data_remove(u.ctx, cdata)
	return newError(int(i))
}

// DebugOut wraps Unbound's ub_ctx_debugout.
func (u *Unbound) DebugOut(out *os.File) error {
	cmode := C.CString("a+")
	defer C.free(unsafe.Pointer(cmode))
	file := C.fdopen(C.int(out.Fd()), cmode)
	i := C.ub_ctx_debugout(u.ctx, unsafe.Pointer(file))
	return newError(int(i))
}

// DebugLevel wraps Unbound's ub_ctx_data_level.
func (u *Unbound) DebugLevel(d int) error {
	i := C.ub_ctx_debuglevel(u.ctx, C.int(d))
	return newError(int(i))
}

// Version wrap Ubounds's ub_version. Return the version of the Unbound
// library in as integers [major, minor, patch]
func (u *Unbound) Version() (version [3]int) {
	// split the string on the dots
	v := strings.SplitN(C.GoString(C.ub_version()), ".", 3)
	if len(v) != 3 {
		return
	}
	version[0], _ = strconv.Atoi(v[0])
	version[1], _ = strconv.Atoi(v[1])
	version[2], _ = strconv.Atoi(v[2])
	return
}
