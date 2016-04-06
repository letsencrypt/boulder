package main

import (
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/core"

	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/test"
)

var log = mocks.UseMockLog()

type mockSA struct {
	certificate core.Certificate
}

func (m *mockSA) AddCertificate(der []byte, _ int64) (string, error) {
	m.certificate.DER = der
	return "", nil
}

func (m *mockSA) GetCertificate(string) (core.Certificate, error) {
	if m.certificate.DER != nil {
		return m.certificate, nil
	}
	return core.Certificate{}, core.NotFoundError("no cert stored")
}

func checkNoErrors(t *testing.T) {
	logs := log.GetAllMatching("ERR:")
	if len(logs) != 0 {
		t.Errorf("Found error logs:")
		for _, ll := range logs {
			t.Error(ll)
		}
	}
}

func TestParseLine(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}

	found, added := parseLogLine(sa, log, "")
	test.AssertEquals(t, found, false)
	test.AssertEquals(t, added, false)

	found, added = parseLogLine(sa, log, "0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: b64der=[] err=[AMQP-RPC timeout], regID=[1337]")
	test.AssertEquals(t, found, true)
	test.AssertEquals(t, added, false)

	found, added = parseLogLine(sa, log, "0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: b64der=[deadbeef] err=[AMQP-RPC timeout], regID=[]")
	test.AssertEquals(t, found, true)
	test.AssertEquals(t, added, false)

	log.Clear()
	found, added = parseLogLine(sa, log, "0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: b64der=[MIIEWzCCA0OgAwIBAgITAP+gFgYw1hiy61wFEIJLFCdIVjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRoYXBweSBoYWNrZXIgZmFrZSBDQTAeFw0xNTEwMDMwNTIxMDBaFw0xNjAxMDEwNTIxMDBaMBgxFjAUBgNVBAMTDWV4YW1wbGUuY28uYm4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeo/HSH63lWW42pqdwlalHWOS3JGa3REraT3xM9v3psdRwuTtlwf3YlpF/JIzK5JtXyA3CHGSwEGmUMhMNBZ0tg5I0booXnHyUeDVUnGSnpWgMUY+vCly+pI5oT8pjBHdcj6kjnDTx1cstBjsJi9HBcYPHUh78iEZBsvC0FAKsh8cHaEjUNHzvWd1anBdK0lRn25M8le9IxXi6di9SeyFmahmPteH+LYKZtNzrF5HpatB14+ywV8d212T62PCCnUPDLd+YWjo2+t5pZs7IlGhyGh7EerOOrI2kUUBg3tUdKDp4e3xplxvaAfSfdrqkGx+bQ0iqQnng+lVkXWYWRB8NAgMBAAGjggGVMIIBkTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDadDBAEUrnrP/566FLp6DmjrlrbMB8GA1UdIwQYMBaAFPt4TxL5YBWDLJ8XfzQZsy426kGJMGoGCCsGAQUFBwEBBF4wXDAmBggrBgEFBQcwAYYaaHR0cDovL2xvY2FsaG9zdDo0MDAyL29jc3AwMgYIKwYBBQUHMAKGJmh0dHA6Ly9sb2NhbGhvc3Q6NDAwMC9hY21lL2lzc3Vlci1jZXJ0MBgGA1UdEQQRMA+CDWV4YW1wbGUuY28uYm4wJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL2V4YW1wbGUuY29tL2NybDBjBgNVHSAEXDBaMAoGBmeBDAECATAAMEwGAyoDBDBFMCIGCCsGAQUFBwIBFhZodHRwOi8vZXhhbXBsZS5jb20vY3BzMB8GCCsGAQUFBwICMBMMEURvIFdoYXQgVGhvdSBXaWx0MA0GCSqGSIb3DQEBCwUAA4IBAQC7tLmUlxyvouVuIljbRtiL+zYdi/zXVSHAMXTkceqp8/8ucZBZu1fMBkB5SW2FUFd8EnuqhKGOeS3dNr9Pe4dLbUDR0UKIwV045Na+Jet4BbHDdWs3NXAutFhdGIa8ivLBQIbTzlBuVRhJE8g6qqjf5hYL0DXkLNptl2l+0+4xJMm/liCp/mYCGRwbdGUzwdSjACO76QLLSqZhkBF37ZJOuDbJTMBi3QzkOcTs6e4d/gSZpCy7yy6nJDxZ9N9P3XBYIpus+aZAYy29d2shYzE3st8cQfB2Wmb0SHd67sftTAzeudiiNW/4E4IKKH4R1S794apUO07y7pkqep1cz32k] err=[AMQP-RPC timeout], regID=[1001]")
	test.AssertEquals(t, found, true)
	test.AssertEquals(t, added, true)
	checkNoErrors(t)

	log.Clear()
	found, added = parseLogLine(sa, log, "0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: b64der=[MIIEWzCCA0OgAwIBAgITAP+gFgYw1hiy61wFEIJLFCdIVjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRoYXBweSBoYWNrZXIgZmFrZSBDQTAeFw0xNTEwMDMwNTIxMDBaFw0xNjAxMDEwNTIxMDBaMBgxFjAUBgNVBAMTDWV4YW1wbGUuY28uYm4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeo/HSH63lWW42pqdwlalHWOS3JGa3REraT3xM9v3psdRwuTtlwf3YlpF/JIzK5JtXyA3CHGSwEGmUMhMNBZ0tg5I0booXnHyUeDVUnGSnpWgMUY+vCly+pI5oT8pjBHdcj6kjnDTx1cstBjsJi9HBcYPHUh78iEZBsvC0FAKsh8cHaEjUNHzvWd1anBdK0lRn25M8le9IxXi6di9SeyFmahmPteH+LYKZtNzrF5HpatB14+ywV8d212T62PCCnUPDLd+YWjo2+t5pZs7IlGhyGh7EerOOrI2kUUBg3tUdKDp4e3xplxvaAfSfdrqkGx+bQ0iqQnng+lVkXWYWRB8NAgMBAAGjggGVMIIBkTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDadDBAEUrnrP/566FLp6DmjrlrbMB8GA1UdIwQYMBaAFPt4TxL5YBWDLJ8XfzQZsy426kGJMGoGCCsGAQUFBwEBBF4wXDAmBggrBgEFBQcwAYYaaHR0cDovL2xvY2FsaG9zdDo0MDAyL29jc3AwMgYIKwYBBQUHMAKGJmh0dHA6Ly9sb2NhbGhvc3Q6NDAwMC9hY21lL2lzc3Vlci1jZXJ0MBgGA1UdEQQRMA+CDWV4YW1wbGUuY28uYm4wJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL2V4YW1wbGUuY29tL2NybDBjBgNVHSAEXDBaMAoGBmeBDAECATAAMEwGAyoDBDBFMCIGCCsGAQUFBwIBFhZodHRwOi8vZXhhbXBsZS5jb20vY3BzMB8GCCsGAQUFBwICMBMMEURvIFdoYXQgVGhvdSBXaWx0MA0GCSqGSIb3DQEBCwUAA4IBAQC7tLmUlxyvouVuIljbRtiL+zYdi/zXVSHAMXTkceqp8/8ucZBZu1fMBkB5SW2FUFd8EnuqhKGOeS3dNr9Pe4dLbUDR0UKIwV045Na+Jet4BbHDdWs3NXAutFhdGIa8ivLBQIbTzlBuVRhJE8g6qqjf5hYL0DXkLNptl2l+0+4xJMm/liCp/mYCGRwbdGUzwdSjACO76QLLSqZhkBF37ZJOuDbJTMBi3QzkOcTs6e4d/gSZpCy7yy6nJDxZ9N9P3XBYIpus+aZAYy29d2shYzE3st8cQfB2Wmb0SHd67sftTAzeudiiNW/4E4IKKH4R1S794apUO07y7pkqep1cz32k] err=[AMQP-RPC timeout], regID=[1001]")
	test.AssertEquals(t, found, true)
	test.AssertEquals(t, added, false)
	checkNoErrors(t)
}

func TestBase64Padding(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}

	log.Clear()
	found, added := parseLogLine(sa, log, `
"1459528419376","04/01/2016 16:33:39.376 +0000","2016-04-01T16:33:39.376647+00:00 staging dc 3 boulder-ca[11111]: [AUDIT] Failed RPC to store at SA, orphaning certificate: serial=[fa8b409b865dd77bd203b325624fabf19474] b64der=[MIIEaDCCA1CgAwIBAgITAPqLQJuGXdd70gOzJWJPq/GUdDANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDDBdGYWtlIExFIEludGVybWVkaWF0ZSBYMTAeFw0xNjA0MDExNTM0MDBaFw0xNjA2MzAxNTM0MDBaMEsxGjAYBgNVBAMTEWRlZGloLmZpcnN0dm0ubmV0MS0wKwYDVQQFEyRmYThiNDA5Yjg2NWRkNzdiZDIwM2IzMjU2MjRmYWJmMTk0NzQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASmfqA+3kb3yq2M+pOV+J3McEfieBEEoeUjKG6/emkCphZCeQQ4+/+6FIZEsVHvUeGB2lkadU5EYM41JN7yiwd80sN6SV36yrsRrhLGZ8ONpo/Q38c7YZsmIfv/g6SrvH+jggIaMIICFjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFCS41AfMhlnhMOh67w1jeTYBayMzMB8GA1UdIwQYMBaAFMDMA0a5WCDMXHJw8+EuyyCm9Wg6MHgGCCsGAQUFBwEBBGwwajAzBggrBgEFBQcwAYYnaHR0cDovL29jc3Auc3RnLWludC14MS5sZXRzZW5jcnlwdC5vcmcvMDMGCCsGAQUFBzAChidodHRwOi8vY2VydC5zdGctaW50LXgxLmxldHNlbmNyeXB0Lm9yZy8wHAYDVR0RBBUwE4IRZGVkaWguZmlyc3R2bS5uZXQwgf4GA1UdIASB9jCB8zAIBgZngQwBAgEwgeYGCysGAQQBgt8TAQEBMIHWMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRpZmljYXRlIG1heSBvbmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGllcyBhbmQgb25seSBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIENlcnRpZmljYXRlIFBvbGljeSBmb3VuZCBhdCBodHRwczovL2xldHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAKmaeuOS5U6HPPddv8UCmzvOnoVsPq2c++bqmjLjKX8QZrzrVBUiTj5aPM1f4e55nOoGPz9RrXzwoce/MAX2X/YlvG1rxmCshi4/m90keA198kwmmGoPQKtR001D0kFJ2fC9P3omI4K3q24nG2j3SxFFBIcMG2LjEtVYqf2ftBxHBY1hp7DI32wt6Lrs7T/jbv69u2BlKCukmkAxWoig0n4LxaOxZa7KrwCdbLJwipy44WJUVQcJgdf1fTtmRitmIMkCjNo1g8czhYdX3sIo8glYtlBLC8JBokphK72DzSeLSPO2sFQ73URtBzzh60MYLq0GUVM8QfXMxbX+xdWNBgA==] err=[AMQP-RPC timeout], regID=[999999]"
	`)
	test.AssertEquals(t, found, true)
	test.AssertEquals(t, added, true)
	checkNoErrors(t)
}

func TestNotOrphan(t *testing.T) {
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa := &mockSA{}

	log.Clear()
	found, added := parseLogLine(sa, log, "base64der=fakeout")
	test.AssertEquals(t, found, false)
	test.AssertEquals(t, added, false)
	checkNoErrors(t)
}
