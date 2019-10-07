package va

import (
	"errors"
	"sync"

	yaml "gopkg.in/yaml.v2"
)

// MultiVAPolicy is a structure containing a map of disabled account IDs and
// domains that should not have multi-VA enforcement applied. It is safe to use
// concurrently and is designed to be live-updated with the reloader package.
type MultiVAPolicy struct {
	disabledDomains  map[string]bool
	disabledAccounts map[int64]bool
	sync.RWMutex
}

var (
	// errEmptyMultiVAPolicy is returned from LoadPolicy when the new policy
	// content is empty or doesn't specify at least one domain or account ID.
	errEmptyMultiVAPolicy = errors.New(
		"MultiVAPolicy must include at least one disabledDomain or disabledAccount")
)

// EnabledDomain returns true if the given domain has multi-VA enabled by
// policy or false otherwise. It is safe to call concurrently.
func (p *MultiVAPolicy) EnabledDomain(domain string) bool {
	// If the policy is nil then multi VA is enabled for all domains.
	if p == nil {
		return true
	}
	p.RLock()
	defer p.RUnlock()
	return !p.disabledDomains[domain]
}

// EnabledAccount returns true if the given account ID has multi-VA enabled by
// policy or false otherwise. It is safe to call concurrently.
func (p *MultiVAPolicy) EnabledAccount(acctID int64) bool {
	// If the policy is nil then multi VA is enabled for all accounts.
	if p == nil {
		return true
	}
	p.RLock()
	defer p.RUnlock()
	return !p.disabledAccounts[acctID]
}

// LoadPolicy loads the given yamlBytes into the multi VA policy. The new policy
// must specify at least one domain or account ID or an error is returned. The
// new policy contents will completely replace the old contents. It is safe to
// call concurrently and is designed to work with the reloader package as
// a dataCallback.
func (p *MultiVAPolicy) LoadPolicy(yamlBytes []byte) error {
	if len(yamlBytes) == 0 {
		return errEmptyMultiVAPolicy
	}

	// Unmarshal the YAML into a throw-away struct containing lists of domain
	// names and IDs.
	var policyObject struct {
		DisabledDomains  []string `yaml:"disabledDomains"`
		DisabledAccounts []int64  `yaml:"disabledAccounts"`
	}
	if err := yaml.Unmarshal(yamlBytes, &policyObject); err != nil {
		return err
	}

	// If there isn't content in one of the lists return an error. This will help
	// catch YAML mistakes that would otherwise result in empty policy going
	// undetected.
	if len(policyObject.DisabledDomains) == 0 && len(policyObject.DisabledAccounts) == 0 {
		return errEmptyMultiVAPolicy
	}

	// Create a lookup map for the disabled domains.
	disabledDomainsMap := make(map[string]bool, len(policyObject.DisabledDomains))
	for _, d := range policyObject.DisabledDomains {
		disabledDomainsMap[d] = true
	}
	// Create a lookup map for the disabled accounts.
	disabledAccountsMap := make(map[int64]bool, len(policyObject.DisabledAccounts))
	for _, acct := range policyObject.DisabledAccounts {
		disabledAccountsMap[acct] = true
	}

	// Finally lock the real policy object and update its maps with the maps
	// created from the new YAML content.
	p.Lock()
	defer p.Unlock()
	p.disabledDomains = disabledDomainsMap
	p.disabledAccounts = disabledAccountsMap
	return nil
}
