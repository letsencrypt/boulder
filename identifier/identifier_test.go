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
			Name:        "Populated identifier, populated name, same values",
			InputIdent:  &corepb.Identifier{Type: "dns", Value: "example.com"},
			InputName:   "example.com",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "example.com"},
			ExpectName:  "example.com",
		},
		{
			Name:        "Populated identifier, populated name, different values",
			InputIdent:  &corepb.Identifier{Type: "dns", Value: "coffee.example.com"},
			InputName:   "tea.example.com",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "coffee.example.com"},
			ExpectName:  "tea.example.com",
		},
		{
			Name:        "Populated identifier, empty name",
			InputIdent:  &corepb.Identifier{Type: "dns", Value: "example.com"},
			InputName:   "",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "example.com"},
			ExpectName:  "example.com",
		},
		{
			Name:        "Empty identifier, populated name",
			InputIdent:  &corepb.Identifier{},
			InputName:   "example.com",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "example.com"},
			ExpectName:  "example.com",
		},
		{
			Name:        "Empty identifier, empty name",
			InputIdent:  &corepb.Identifier{},
			InputName:   "",
			ExpectIdent: ACMEIdentifier{},
			ExpectName:  "",
		},
		{
			Name:        "Nil identifier, populated name",
			InputIdent:  nil,
			InputName:   "example.com",
			ExpectIdent: ACMEIdentifier{Type: TypeDNS, Value: "example.com"},
			ExpectName:  "example.com",
		},
		{
			Name:        "Nil identifier, empty name",
			InputIdent:  nil,
			InputName:   "",
			ExpectIdent: ACMEIdentifier{},
			ExpectName:  "",
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
			Name: "Populated identifiers, populated names, same values",
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
			Name: "Populated identifiers, populated names, different values",
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
			Name: "Populated identifiers, empty names",
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
			Name: "Populated identifiers, nil names",
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
			Name:        "Empty identifiers, populated names",
			InputIdents: []*corepb.Identifier{},
			InputNames:  []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
			ExpectNames: []string{"a.example.com", "b.example.com"},
		},
		{
			Name:         "Empty identifiers, empty names",
			InputIdents:  []*corepb.Identifier{},
			InputNames:   []string{},
			ExpectIdents: nil,
			ExpectNames:  nil,
		},
		{
			Name:         "Empty identifiers, nil names",
			InputIdents:  []*corepb.Identifier{},
			InputNames:   nil,
			ExpectIdents: nil,
			ExpectNames:  nil,
		},
		{
			Name:        "Nil identifiers, populated names",
			InputIdents: nil,
			InputNames:  []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
			ExpectNames: []string{"a.example.com", "b.example.com"},
		},
		{
			Name:         "Nil identifiers, empty names",
			InputIdents:  nil,
			InputNames:   []string{},
			ExpectIdents: nil,
			ExpectNames:  nil,
		},
		{
			Name:         "Nil identifiers, nil names",
			InputIdents:  nil,
			InputNames:   nil,
			ExpectIdents: nil,
			ExpectNames:  nil,
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
