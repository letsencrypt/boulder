// Package publicsuffix provides a domain name parser
// based on data from the public suffix list http://publicsuffix.org/.
// A public suffix is one under which Internet users can directly register names.
package publicsuffix

import (
	"bufio"
	"fmt"
	"io"
	"net/http/cookiejar"
	"os"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

const (
	// Version identifies the current library version.
	// This is a pro-forma convention given that Go dependencies
	// tends to be fetched directly from the repo.
	Version = "0.4.0"

	NormalType    = 1
	WildcardType  = 2
	ExceptionType = 3

	listTokenPrivateDomains = "===BEGIN PRIVATE DOMAINS==="
	listTokenComment        = "//"
)

// DefaultList is the default List and it is used by Parse and Domain.
var DefaultList = NewList()

// DefaultRule is the default Rule that represents "*".
var DefaultRule = MustNewRule("*")

// DefaultParserOptions are the default options used to parse a Public Suffix list.
var DefaultParserOptions = &ParserOption{PrivateDomains: true, ASCIIEncoded: false}

// DefaultFindOptions are the default options used to perform the lookup of rules in the list.
var DefaultFindOptions = &FindOptions{IgnorePrivate: false, DefaultRule: DefaultRule}

// Rule represents a single rule in a Public Suffix List.
type Rule struct {
	Type    int
	Value   string
	Length  int
	Private bool
}

// ParserOption are the options you can use to customize the way a List
// is parsed from a file or a string.
type ParserOption struct {
	// Set to false to skip the private domains when parsing.
	// Default to true, which means the private domains are included.
	PrivateDomains bool

	// Set to false if the input is encoded in U-labels (Unicode)
	// as opposite to A-labels.
	// Default to false, which means the list is containing Unicode domains.
	// This is the default because the original PSL currently contains Unicode.
	ASCIIEncoded bool
}

// FindOptions are the options you can use to customize the way a Rule
// is searched within the list.
type FindOptions struct {
	// Set to true to ignore the rules within the "Private" section of the Public Suffix List.
	IgnorePrivate bool

	// The default rule to use when no rule matches the input.
	// The format Public Suffix algorithm states that the rule "*" should be used when no other rule matches,
	// but some consumers may have different needs.
	DefaultRule *Rule
}

// List represents a Public Suffix List.
type List struct {
	// rules is kept private because you should not access rules directly
	// for lookup optimization the list will not be guaranteed to be a simple slice forever
	rules []Rule
}

// NewList creates a new empty list.
func NewList() *List {
	return &List{}
}

// NewListFromString parses a string that represents a Public Suffix source
// and returns a List initialized with the rules in the source.
func NewListFromString(src string, options *ParserOption) (*List, error) {
	l := NewList()
	_, err := l.LoadString(src, options)
	return l, err
}

// NewListFromFile parses a string that represents a Public Suffix source
// and returns a List initialized with the rules in the source.
func NewListFromFile(path string, options *ParserOption) (*List, error) {
	l := NewList()
	_, err := l.LoadFile(path, options)
	return l, err
}

// Load parses and loads a set of rules from an io.Reader into the current list.
func (l *List) Load(r io.Reader, options *ParserOption) ([]Rule, error) {
	return l.parse(r, options)
}

// LoadString parses and loads a set of rules from a String into the current list.
func (l *List) LoadString(src string, options *ParserOption) ([]Rule, error) {
	r := strings.NewReader(src)
	return l.parse(r, options)
}

// LoadFile parses and loads a set of rules from a File into the current list.
func (l *List) LoadFile(path string, options *ParserOption) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return l.parse(f, options)
}

// AddRule adds a new rule to the list.
//
// The exact position of the rule into the list is unpredictable.
// The list may be optimized internally for lookups, therefore the algorithm
// will decide the best position for the new rule.
func (l *List) AddRule(r *Rule) error {
	l.rules = append(l.rules, *r)
	return nil
}

// Size returns the size of the list, which is the number of rules.
func (l *List) Size() int {
	return len(l.rules)
}

func (l *List) parse(r io.Reader, options *ParserOption) ([]Rule, error) {
	if options == nil {
		options = DefaultParserOptions
	}
	var rules []Rule

	scanner := bufio.NewScanner(r)
	var section int // 1 == ICANN, 2 == PRIVATE

Scanning:
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {

		// skip blank lines
		case line == "":
			break

		// include private domains or stop scanner
		case strings.Contains(line, listTokenPrivateDomains):
			if !options.PrivateDomains {
				break Scanning
			}
			section = 2

		// skip comments
		case strings.HasPrefix(line, listTokenComment):
			break

		default:
			var rule *Rule
			var err error

			if options.ASCIIEncoded {
				rule, err = NewRule(line)
			} else {
				rule, err = NewRuleUnicode(line)
			}
			if err != nil {
				return []Rule{}, err
			}

			rule.Private = (section == 2)
			l.AddRule(rule)
			rules = append(rules, *rule)
		}

	}

	return rules, scanner.Err()
}

// Find and returns the most appropriate rule for the domain name.
func (l *List) Find(name string, options *FindOptions) *Rule {
	var bestRule *Rule

	if options == nil {
		options = DefaultFindOptions
	}

	for _, r := range l.selectRules(name, options) {
		if r.Type == ExceptionType {
			return &r
		}
		if bestRule == nil || bestRule.Length < r.Length {
			bestRule = &r
		}
	}

	if bestRule != nil {
		return bestRule
	}

	return options.DefaultRule
}

func (l *List) selectRules(name string, options *FindOptions) []Rule {
	var found []Rule

	// In this phase the search is a simple sequential scan
	for _, rule := range l.rules {
		if !rule.Match(name) {
			continue
		}
		if options.IgnorePrivate && rule.Private {
			continue
		}
		found = append(found, rule)
	}

	return found
}

// NewRule parses the rule content, creates and returns a Rule.
//
// The content of the rule MUST be encoded in ASCII (A-labels).
func NewRule(content string) (*Rule, error) {
	var rule *Rule
	var value string

	switch content[0:1] {
	case "*": // wildcard
		if content == "*" {
			value = ""
		} else {
			value = content[2:]
		}
		rule = &Rule{Type: WildcardType, Value: value, Length: len(Labels(value)) + 1}
	case "!": // exception
		value = content[1:]
		rule = &Rule{Type: ExceptionType, Value: value, Length: len(Labels(value))}
	default: // normal
		value = content
		rule = &Rule{Type: NormalType, Value: value, Length: len(Labels(value))}
	}

	return rule, nil
}

// NewRuleUnicode is like NewRule, but expects the content to be encoded in Unicode (U-labels).
func NewRuleUnicode(content string) (*Rule, error) {
	var err error

	content, err = ToASCII(content)
	if err != nil {
		return nil, err
	}

	return NewRule(content)
}

// MustNewRule is like NewRule, but panics if the content cannot be parsed.
func MustNewRule(content string) *Rule {
	rule, err := NewRule(content)
	if err != nil {
		panic(err)
	}
	return rule
}

// Match checks if the rule matches the name.
//
// A domain name is said to match a rule if and only if all of the following conditions are met:
// - When the domain and rule are split into corresponding labels,
//   that the domain contains as many or more labels than the rule.
// - Beginning with the right-most labels of both the domain and the rule,
//   and continuing for all labels in the rule, one finds that for every pair,
//   either they are identical, or that the label from the rule is "*".
//
// See https://publicsuffix.org/list/
func (r *Rule) Match(name string) bool {
	left := strings.TrimSuffix(name, r.Value)

	// the name contains as many labels than the rule
	// this is a match, unless it's a wildcard
	// because the wildcard requires one more label
	if left == "" {
		return r.Type != WildcardType
	}

	// if there is one more label, the rule match
	// because either the rule is shorter than the domain
	// or the rule is a wildcard and there is one more label
	return left[len(left)-1:] == "."
}

// Decompose takes a name as input and decomposes it into a tuple of <TRD+SLD, TLD>,
// according to the rule definition and type.
func (r *Rule) Decompose(name string) [2]string {
	var parts []string

	switch r.Type {
	case WildcardType:
		parts = append([]string{`.*?`}, r.parts()...)
	default:
		parts = r.parts()
	}

	suffix := strings.Join(parts, `\.`)
	re := regexp.MustCompile(fmt.Sprintf(`^(.+)\.(%s)$`, suffix))

	matches := re.FindStringSubmatch(name)
	if len(matches) < 3 {
		return [2]string{"", ""}
	}

	return [2]string{matches[1], matches[2]}
}

func (r *Rule) parts() []string {
	labels := Labels(r.Value)
	if r.Type == ExceptionType {
		return labels[1:]
	}
	if r.Type == WildcardType && r.Value == "" {
		return []string{}
	}
	return labels
}

// Labels decomposes given domain name into labels,
// corresponding to the dot-separated tokens.
func Labels(name string) []string {
	return strings.Split(name, ".")
}

// DomainName represents a domain name.
type DomainName struct {
	TLD  string
	SLD  string
	TRD  string
	Rule *Rule
}

// String joins the components of the domain name into a single string.
// Empty labels are skipped.
//
// Examples:
//
// 	DomainName{"com", "example"}.String()
//	// example.com
// 	DomainName{"com", "example", "www"}.String()
//	// www.example.com
//
func (d *DomainName) String() string {
	switch {
	case d.TLD == "":
		return ""
	case d.SLD == "":
		return d.TLD
	case d.TRD == "":
		return d.SLD + "." + d.TLD
	default:
		return d.TRD + "." + d.SLD + "." + d.TLD
	}
}

// Domain extract and return the domain name from the input
// using the default (Public Suffix) List.
//
// Examples:
//
// 	publicsuffix.Domain("example.com")
//	// example.com
// 	publicsuffix.Domain("www.example.com")
//	// example.com
// 	publicsuffix.Domain("www.example.co.uk")
//	// example.co.uk
//
func Domain(name string) (string, error) {
	return DomainFromListWithOptions(DefaultList, name, DefaultFindOptions)
}

// Parse decomposes the name into TLD, SLD, TRD
// using the default (Public Suffix) List,
// and returns the result as a DomainName
//
// Examples:
//
//	list := NewList()
//
// 	publicsuffix.Parse("example.com")
//	// &DomainName{"com", "example"}
// 	publicsuffix.Parse("www.example.com")
//	// &DomainName{"com", "example", "www"}
// 	publicsuffix.Parse("www.example.co.uk")
//	// &DomainName{"co.uk", "example"}
//
func Parse(name string) (*DomainName, error) {
	return ParseFromListWithOptions(DefaultList, name, DefaultFindOptions)
}

// DomainFromListWithOptions extract and return the domain name from the input
// using the (Public Suffix) list passed as argument.
//
// Examples:
//
//	list := NewList()
//
// 	publicsuffix.DomainFromListWithOptions(list, "example.com")
//	// example.com
// 	publicsuffix.DomainFromListWithOptions(list, "www.example.com")
//	// example.com
// 	publicsuffix.DomainFromListWithOptions(list, "www.example.co.uk")
//	// example.co.uk
//
func DomainFromListWithOptions(l *List, name string, options *FindOptions) (string, error) {
	dn, err := ParseFromListWithOptions(l, name, options)
	if err != nil {
		return "", err
	}

	return dn.SLD + "." + dn.TLD, nil
}

// ParseFromListWithOptions decomposes the name into TLD, SLD, TRD
// using the (Public Suffix) list passed as argument,
// and returns the result as a DomainName
//
// Examples:
//
//	list := NewList()
//
// 	publicsuffix.ParseFromListWithOptions(list, "example.com")
//	// &DomainName{"com", "example"}
// 	publicsuffix.ParseFromListWithOptions(list, "www.example.com")
//	// &DomainName{"com", "example", "www"}
// 	publicsuffix.ParseFromListWithOptions(list, "www.example.co.uk")
//	// &DomainName{"co.uk", "example"}
//
func ParseFromListWithOptions(l *List, name string, options *FindOptions) (*DomainName, error) {
	n, err := normalize(name)
	if err != nil {
		return nil, err
	}

	r := l.Find(n, options)
	if tld := r.Decompose(n)[1]; tld == "" {
		return nil, fmt.Errorf("%s is a suffix", n)
	}

	dn := &DomainName{Rule: r}
	dn.TLD, dn.SLD, dn.TRD = decompose(r, n)
	return dn, nil
}

func normalize(name string) (string, error) {
	ret := strings.ToLower(name)

	if ret == "" {
		return "", fmt.Errorf("Name is blank")
	}
	if ret[0] == '.' {
		return "", fmt.Errorf("Name %s starts with a dot", ret)
	}

	return ret, nil
}

func decompose(r *Rule, name string) (tld, sld, trd string) {
	parts := r.Decompose(name)
	left, tld := parts[0], parts[1]

	dot := strings.LastIndex(left, ".")
	if dot == -1 {
		sld = left
		trd = ""
	} else {
		sld = left[dot+1:]
		trd = left[0:dot]
	}

	return
}

// ToASCII is a wrapper for idna.ToASCII.
//
// This wrapper exists because idna.ToASCII backward-compatibility was broken twice in few months
// and I can't call this package directly anymore. The wrapper performs some terrible-but-necessary
// before-after replacements to make sure an already ASCII input always results in the same output
// even if passed through ToASCII.
//
// See golang/net@67957fd0b1, golang/net@f2499483f9, golang/net@78ebe5c8b6,
// and weppos/publicsuffix-go#66.
func ToASCII(s string) (string, error) {
	// .example.com should be .example.com
	// ..example.com should be ..example.com
	if strings.HasPrefix(s, ".") {
		dotIndex := 0
		for i := 0; i < len(s); i++ {
			if s[i] == '.' {
				dotIndex = i
			} else {
				break
			}
		}
		out, err := idna.ToASCII(s[dotIndex+1:])
		out = s[:dotIndex+1] + out
		return out, err
	}

	return idna.ToASCII(s)
}

// ToUnicode is a wrapper for idna.ToUnicode.
//
// See ToASCII for more details about why this wrapper exists.
func ToUnicode(s string) (string, error) {
	return idna.ToUnicode(s)
}

// CookieJarList implements the cookiejar.PublicSuffixList interface.
var CookieJarList cookiejar.PublicSuffixList = cookiejarList{DefaultList}

type cookiejarList struct {
	List *List
}

// PublicSuffix implements cookiejar.PublicSuffixList.
func (l cookiejarList) PublicSuffix(domain string) string {
	rule := l.List.Find(domain, nil)
	return rule.Decompose(domain)[1]
}

// PublicSuffix implements cookiejar.String.
func (cookiejarList) String() string {
	return defaultListVersion
}
