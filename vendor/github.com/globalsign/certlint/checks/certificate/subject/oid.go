package subject

import (
	"encoding/asn1"
	"fmt"
)

// Max field length:
// https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2001/UpperBounds.html
type object struct {
	oid       asn1.ObjectIdentifier
	maxLength int
}

func (o *object) Equal(oid asn1.ObjectIdentifier) bool {
	return o.oid.Equal(oid)
}

func (o *object) Valid(v interface{}) error {
	if o.maxLength > 0 && len([]rune(v.(string))) > o.maxLength {
		return fmt.Errorf("exeeding max lenght of %d", o.maxLength)
	}
	return nil
}

// http://www.alvestrand.no/objectid/2.5.4.html
var (
	objectClass                 = object{asn1.ObjectIdentifier{2, 5, 4, 0}, 0}
	aliasedEntryName            = object{asn1.ObjectIdentifier{2, 5, 4, 1}, 0}
	knowldgeinformation         = object{asn1.ObjectIdentifier{2, 5, 4, 2}, 0}
	commonName                  = object{asn1.ObjectIdentifier{2, 5, 4, 3}, 64}
	surname                     = object{asn1.ObjectIdentifier{2, 5, 4, 4}, 40}
	serialNumber                = object{asn1.ObjectIdentifier{2, 5, 4, 5}, 64}
	countryName                 = object{asn1.ObjectIdentifier{2, 5, 4, 6}, 2}
	localityName                = object{asn1.ObjectIdentifier{2, 5, 4, 7}, 128}
	stateOrProvinceName         = object{asn1.ObjectIdentifier{2, 5, 4, 8}, 128}
	streetAddress               = object{asn1.ObjectIdentifier{2, 5, 4, 9}, 128}
	organizationName            = object{asn1.ObjectIdentifier{2, 5, 4, 10}, 64}
	organizationalUnitName      = object{asn1.ObjectIdentifier{2, 5, 4, 11}, 64}
	title                       = object{asn1.ObjectIdentifier{2, 5, 4, 12}, 64}
	description                 = object{asn1.ObjectIdentifier{2, 5, 4, 13}, 1024}
	searchGuide                 = object{asn1.ObjectIdentifier{2, 5, 4, 14}, 32768}
	businessCategory            = object{asn1.ObjectIdentifier{2, 5, 4, 15}, 128}
	postalAddress               = object{asn1.ObjectIdentifier{2, 5, 4, 16}, 128}
	postalCode                  = object{asn1.ObjectIdentifier{2, 5, 4, 17}, 40}
	postOfficeBox               = object{asn1.ObjectIdentifier{2, 5, 4, 18}, 40}
	physicalDeliveryOfficeName  = object{asn1.ObjectIdentifier{2, 5, 4, 19}, 128}
	telephoneNumber             = object{asn1.ObjectIdentifier{2, 5, 4, 20}, 32}
	telexNumber                 = object{asn1.ObjectIdentifier{2, 5, 4, 21}, 14}
	teletexTerminalIdentifier   = object{asn1.ObjectIdentifier{2, 5, 4, 22}, 1024}
	facsimileTelephoneNumber    = object{asn1.ObjectIdentifier{2, 5, 4, 23}, 32}
	x121Address                 = object{asn1.ObjectIdentifier{2, 5, 4, 24}, 15}
	internationalISDNNumber     = object{asn1.ObjectIdentifier{2, 5, 4, 25}, 16}
	registeredAddress           = object{asn1.ObjectIdentifier{2, 5, 4, 26}, 128}
	destinationIndicator        = object{asn1.ObjectIdentifier{2, 5, 4, 27}, 128}
	preferredDeliveryMethod     = object{asn1.ObjectIdentifier{2, 5, 4, 28}, 0}
	presentationAddress         = object{asn1.ObjectIdentifier{2, 5, 4, 29}, 0}
	supportedApplicationContext = object{asn1.ObjectIdentifier{2, 5, 4, 30}, 0}
	member                      = object{asn1.ObjectIdentifier{2, 5, 4, 31}, 0}
	owner                       = object{asn1.ObjectIdentifier{2, 5, 4, 32}, 0}
	roleOccupant                = object{asn1.ObjectIdentifier{2, 5, 4, 33}, 0}
	seeAlso                     = object{asn1.ObjectIdentifier{2, 5, 4, 34}, 0}
	userPassword                = object{asn1.ObjectIdentifier{2, 5, 4, 35}, 128}
	userCertificate             = object{asn1.ObjectIdentifier{2, 5, 4, 36}, 0}
	cACertificate               = object{asn1.ObjectIdentifier{2, 5, 4, 37}, 0}
	authorityRevocationList     = object{asn1.ObjectIdentifier{2, 5, 4, 38}, 0}
	certificateRevocationList   = object{asn1.ObjectIdentifier{2, 5, 4, 39}, 0}
	crossCertificatePair        = object{asn1.ObjectIdentifier{2, 5, 4, 40}, 0}
	name                        = object{asn1.ObjectIdentifier{2, 5, 4, 41}, 128}
	givenName                   = object{asn1.ObjectIdentifier{2, 5, 4, 42}, 128}
	initials                    = object{asn1.ObjectIdentifier{2, 5, 4, 43}, 0}
	generationQualifier         = object{asn1.ObjectIdentifier{2, 5, 4, 44}, 0}
	uniqueIdentifier            = object{asn1.ObjectIdentifier{2, 5, 4, 45}, 0}
	dnQualifier                 = object{asn1.ObjectIdentifier{2, 5, 4, 46}, 0}
	enhancedSearchGuide         = object{asn1.ObjectIdentifier{2, 5, 4, 47}, 0}
	protocolInformation         = object{asn1.ObjectIdentifier{2, 5, 4, 48}, 0}
	distinguishedName           = object{asn1.ObjectIdentifier{2, 5, 4, 49}, 0}
	uniqueMember                = object{asn1.ObjectIdentifier{2, 5, 4, 50}, 0}
	houseIdentifier             = object{asn1.ObjectIdentifier{2, 5, 4, 51}, 0}
	supportedAlgorithms         = object{asn1.ObjectIdentifier{2, 5, 4, 52}, 0}
	deltaRevocationList         = object{asn1.ObjectIdentifier{2, 5, 4, 53}, 0}
	attributeCertificate        = object{asn1.ObjectIdentifier{2, 5, 4, 58}, 0}
	pseudonym                   = object{asn1.ObjectIdentifier{2, 5, 4, 65}, 0}

	emailAddress = object{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, 255}

	jurisdictionLocalityName        = object{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}, 128}
	jurisdictionStateOrProvinceName = object{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}, 128}
	jurisdictionCountryName         = object{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}, 2}
)
