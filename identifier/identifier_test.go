package identifier

import (
	"testing"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/test"
)

func TestNormalizeIdentifiers(t *testing.T) {
	idents := []ACMEIdentifier{
		{Type: "DNS", Value: "foobar.com"},
		{Type: "DNS", Value: "fooBAR.com"},
		{Type: "DNS", Value: "baz.com"},
		{Type: "DNS", Value: "foobar.com"},
		{Type: "DNS", Value: "bar.com"},
		{Type: "DNS", Value: "bar.com"},
		{Type: "DNS", Value: "a.com"},
	}
	expected := []ACMEIdentifier{
		{Type: "DNS", Value: "a.com"},
		{Type: "DNS", Value: "bar.com"},
		{Type: "DNS", Value: "baz.com"},
		{Type: "DNS", Value: "foobar.com"},
	}
	u := Normalize(idents)
	test.AssertDeepEquals(t, expected, u)
}

func TestSliceFromProto(t *testing.T) {
	testCases := []struct {
		Name         string
		InputIdents  []*corepb.Identifier
		InputNames   []string
		ExpectIdents []ACMEIdentifier
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
		},
		{
			Name:        "Empty identifiers, populated names",
			InputIdents: []*corepb.Identifier{},
			InputNames:  []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
		},
		{
			Name:         "Empty identifiers, empty names",
			InputIdents:  []*corepb.Identifier{},
			InputNames:   []string{},
			ExpectIdents: nil,
		},
		{
			Name:         "Empty identifiers, nil names",
			InputIdents:  []*corepb.Identifier{},
			InputNames:   nil,
			ExpectIdents: nil,
		},
		{
			Name:        "Nil identifiers, populated names",
			InputIdents: nil,
			InputNames:  []string{"a.example.com", "b.example.com"},
			ExpectIdents: []ACMEIdentifier{
				{Type: TypeDNS, Value: "a.example.com"},
				{Type: TypeDNS, Value: "b.example.com"},
			},
		},
		{
			Name:         "Nil identifiers, empty names",
			InputIdents:  nil,
			InputNames:   []string{},
			ExpectIdents: nil,
		},
		{
			Name:         "Nil identifiers, nil names",
			InputIdents:  nil,
			InputNames:   nil,
			ExpectIdents: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			idents := SliceFromProto(tc.InputIdents, tc.InputNames)
			test.AssertDeepEquals(t, idents, tc.ExpectIdents)
		})
	}
}
