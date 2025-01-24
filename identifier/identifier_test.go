package identifier

import (
	"testing"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/test"
)

func TestIdentifierAndName(t *testing.T) {
	testCases := []struct {
		Name        string
		InputIdent  *corepb.Identifier
		InputName   string
		ExpectIdent ACMEIdentifier
		ExpectName  string
	}{
		{
			Name:        "Identical values",
			InputIdent:  &corepb.Identifier{Type: "dns", Value: "example.com"},
			InputName:   "example.com",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "example.com"},
			ExpectName:  "example.com",
		},
		{
			Name:        "Different values",
			InputIdent:  &corepb.Identifier{Type: "dns", Value: "coffee.example.com"},
			InputName:   "tea.example.com",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "coffee.example.com"},
			ExpectName:  "tea.example.com",
		},
		{
			Name:        "Identifier, empty name",
			InputIdent:  &corepb.Identifier{Type: "dns", Value: "example.com"},
			InputName:   "",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "example.com"},
			ExpectName:  "example.com",
		},
		{
			Name:        "Name, nil identifier",
			InputIdent:  nil,
			InputName:   "example.com",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "example.com"},
			ExpectName:  "example.com",
		},
		{
			Name:        "Name, empty identifier",
			InputIdent:  &corepb.Identifier{},
			InputName:   "example.com",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "example.com"},
			ExpectName:  "example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			ident, name := IdentifierAndName(tc.InputIdent, tc.InputName)
			test.AssertEquals(t, ident, tc.ExpectIdent)
			test.AssertEquals(t, name, tc.ExpectName)
		})
	}
}

func TestIdentifiersAndNames(t *testing.T) {
	testCases := []struct {
		Name         string
		InputIdents  []*corepb.Identifier
		InputNames   []string
		ExpectIdents []ACMEIdentifier
		ExpectNames  []string
	}{
		{
			Name: "Identical values",
			InputIdents: []*corepb.Identifier{
				{Type: "dns", Value: "a.example.com"},
				{Type: "dns", Value: "b.example.com"},
			},
			InputNames: []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
			ExpectNames: []string{"a.example.com", "b.example.com"},
		},
		{
			Name: "Different values",
			InputIdents: []*corepb.Identifier{
				{Type: "dns", Value: "coffee.example.com"},
			},
			InputNames: []string{"tea.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "coffee.example.com"},
			},
			ExpectNames: []string{"tea.example.com"},
		},
		{
			Name: "Identifiers, nil names",
			InputIdents: []*corepb.Identifier{
				{Type: "dns", Value: "example.com"},
			},
			InputNames: nil,
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "example.com"},
			},
			ExpectNames: []string{"example.com"},
		},
		{
			Name: "Identifiers, empty names",
			InputIdents: []*corepb.Identifier{
				{Type: "dns", Value: "example.com"},
			},
			InputNames: []string{},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "example.com"},
			},
			ExpectNames: []string{"example.com"},
		},
		{
			Name:        "Names, nil identifiers",
			InputIdents: nil,
			InputNames:  []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
			ExpectNames: []string{"a.example.com", "b.example.com"},
		},
		{
			Name:        "Names, empty identifiers",
			InputIdents: []*corepb.Identifier{},
			InputNames:  []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
			ExpectNames: []string{"a.example.com", "b.example.com"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			idents, names := IdentifiersAndNames(tc.InputIdents, tc.InputNames)
			test.AssertDeepEquals(t, idents, tc.ExpectIdents)
			test.AssertDeepEquals(t, names, tc.ExpectNames)
		})
	}
}
