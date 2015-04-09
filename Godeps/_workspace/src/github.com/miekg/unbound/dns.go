package unbound

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/miekg/dns"
	"math/rand"
	"sort"
)

// AddTaRR calls AddTa, but allows to directly use an dns.RR.
// This method is not found in Unbound.
func (u *Unbound) AddTaRR(ta dns.RR) error { return u.AddTa(ta.String()) }

// DataAddRR calls DataAdd, but allows to directly use an dns.RR.
// This method is not found in Unbound.
func (u *Unbound) DataAddRR(data dns.RR) error { return u.DataAdd(data.String()) }

// DataRemoveRR calls DataRemove, but allows to directly use an dns.RR.
// This method is not found in Unbound.
func (u *Unbound) DataRemoveRR(data dns.RR) error { return u.DataRemove(data.String()) }

// Copied from the standard library

// byPriorityWeight sorts SRV records by ascending priority and weight.
type byPriorityWeight []*dns.SRV

func (s byPriorityWeight) Len() int      { return len(s) }
func (s byPriorityWeight) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byPriorityWeight) Less(i, j int) bool {
	return s[i].Priority < s[j].Priority ||
		(s[i].Priority == s[j].Priority && s[i].Weight < s[j].Weight)
}

// shuffleByWeight shuffles SRV records by weight using the algorithm
// described in RFC 2782.
func (addrs byPriorityWeight) shuffleByWeight() {
	sum := 0
	for _, addr := range addrs {
		sum += int(addr.Weight)
	}
	for sum > 0 && len(addrs) > 1 {
		s := 0
		n := rand.Intn(sum + 1)
		for i := range addrs {
			s += int(addrs[i].Weight)
			if s >= n {
				if i > 0 {
					t := addrs[i]
					copy(addrs[1:i+1], addrs[0:i])
					addrs[0] = t
				}
				break
			}
		}
		sum -= int(addrs[0].Weight)
		addrs = addrs[1:]
	}
}

// sort reorders SRV records as specified in RFC 2782.
func (addrs byPriorityWeight) sort() {
	sort.Sort(addrs)
	i := 0
	for j := 1; j < len(addrs); j++ {
		if addrs[i].Priority != addrs[j].Priority {
			addrs[i:j].shuffleByWeight()
			i = j
		}
	}
	addrs[i:].shuffleByWeight()
}

// byPref implements sort.Interface to sort MX records by preference
type byPref []*dns.MX

func (s byPref) Len() int           { return len(s) }
func (s byPref) Less(i, j int) bool { return s[i].Preference < s[j].Preference }
func (s byPref) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// sort reorders MX records as specified in RFC 5321.
func (s byPref) sort() {
	for i := range s {
		j := rand.Intn(i + 1)
		s[i], s[j] = s[j], s[i]
	}
	sort.Sort(s)
}
