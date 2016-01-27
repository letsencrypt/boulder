package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mocks"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/sa/satest"
	"github.com/letsencrypt/boulder/test"
	"github.com/letsencrypt/boulder/test/vars"
)

var log = mocks.UseMockLog()

func TestParseLine(t *testing.T) {
	dbMap, err := sa.NewDbMap(vars.DBConnSA)
	if err != nil {
		t.Fatalf("Failed to create dbMap: %s", err)
	}
	fc := clock.NewFake()
	fc.Set(time.Date(2015, 3, 4, 5, 0, 0, 0, time.UTC))
	sa, err := sa.NewSQLStorageAuthority(dbMap, fc)
	if err != nil {
		t.Fatalf("Failed to create SA: %s", err)
	}
	defer test.ResetSATestDatabase(t)()
	logger := blog.GetAuditLogger()

	found, added := parseLogLine(sa, logger, "")
	test.AssertEquals(t, found, false)
	test.AssertEquals(t, added, false)

	found, added = parseLogLine(sa, logger, "0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: b64der=[] err=[AMQP-RPC timeout], regID=[1337]")
	test.AssertEquals(t, found, true)
	test.AssertEquals(t, added, false)

	found, added = parseLogLine(sa, logger, "0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: b64der=[deadbeef] err=[AMQP-RPC timeout], regID=[]")
	test.AssertEquals(t, found, true)
	test.AssertEquals(t, added, false)

	reg := satest.CreateWorkingRegistration(t, sa)

	found, added = parseLogLine(sa, logger, fmt.Sprintf("0000-00-00T00:00:00+00:00 hostname boulder-ca[pid]: [AUDIT] Failed RPC to store at SA, orphaning certificate: b64der=[MIIEWzCCA0OgAwIBAgITAP+gFgYw1hiy61wFEIJLFCdIVjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRoYXBweSBoYWNrZXIgZmFrZSBDQTAeFw0xNTEwMDMwNTIxMDBaFw0xNjAxMDEwNTIxMDBaMBgxFjAUBgNVBAMTDWV4YW1wbGUuY28uYm4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCeo/HSH63lWW42pqdwlalHWOS3JGa3REraT3xM9v3psdRwuTtlwf3YlpF/JIzK5JtXyA3CHGSwEGmUMhMNBZ0tg5I0booXnHyUeDVUnGSnpWgMUY+vCly+pI5oT8pjBHdcj6kjnDTx1cstBjsJi9HBcYPHUh78iEZBsvC0FAKsh8cHaEjUNHzvWd1anBdK0lRn25M8le9IxXi6di9SeyFmahmPteH+LYKZtNzrF5HpatB14+ywV8d212T62PCCnUPDLd+YWjo2+t5pZs7IlGhyGh7EerOOrI2kUUBg3tUdKDp4e3xplxvaAfSfdrqkGx+bQ0iqQnng+lVkXWYWRB8NAgMBAAGjggGVMIIBkTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDadDBAEUrnrP/566FLp6DmjrlrbMB8GA1UdIwQYMBaAFPt4TxL5YBWDLJ8XfzQZsy426kGJMGoGCCsGAQUFBwEBBF4wXDAmBggrBgEFBQcwAYYaaHR0cDovL2xvY2FsaG9zdDo0MDAyL29jc3AwMgYIKwYBBQUHMAKGJmh0dHA6Ly9sb2NhbGhvc3Q6NDAwMC9hY21lL2lzc3Vlci1jZXJ0MBgGA1UdEQQRMA+CDWV4YW1wbGUuY28uYm4wJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL2V4YW1wbGUuY29tL2NybDBjBgNVHSAEXDBaMAoGBmeBDAECATAAMEwGAyoDBDBFMCIGCCsGAQUFBwIBFhZodHRwOi8vZXhhbXBsZS5jb20vY3BzMB8GCCsGAQUFBwICMBMMEURvIFdoYXQgVGhvdSBXaWx0MA0GCSqGSIb3DQEBCwUAA4IBAQC7tLmUlxyvouVuIljbRtiL+zYdi/zXVSHAMXTkceqp8/8ucZBZu1fMBkB5SW2FUFd8EnuqhKGOeS3dNr9Pe4dLbUDR0UKIwV045Na+Jet4BbHDdWs3NXAutFhdGIa8ivLBQIbTzlBuVRhJE8g6qqjf5hYL0DXkLNptl2l+0+4xJMm/liCp/mYCGRwbdGUzwdSjACO76QLLSqZhkBF37ZJOuDbJTMBi3QzkOcTs6e4d/gSZpCy7yy6nJDxZ9N9P3XBYIpus+aZAYy29d2shYzE3st8cQfB2Wmb0SHd67sftTAzeudiiNW/4E4IKKH4R1S794apUO07y7pkqep1cz32k] err=[AMQP-RPC timeout], regID=[%d]", reg.ID))
	test.AssertEquals(t, found, true)
	test.AssertEquals(t, added, true)
}
