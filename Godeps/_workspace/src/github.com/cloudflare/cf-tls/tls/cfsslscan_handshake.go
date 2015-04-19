package tls

// SayHello sends a simple Client Hello to server and returns the negotiated ciphersuite ID
func (c *Conn) SayHello() (cipherID uint16, version uint16, err error) {
	hello := &clientHelloMsg{
		vers:                c.config.maxVersion(),
		compressionMethods:  []uint8{compressionNone},
		random:              make([]byte, 32),
		ocspStapling:        true,
		serverName:          c.config.ServerName,
		supportedCurves:     c.config.curvePreferences(),
		supportedPoints:     []uint8{pointFormatUncompressed},
		nextProtoNeg:        len(c.config.NextProtos) > 0,
		secureRenegotiation: true,
		cipherSuites:        c.config.cipherSuites(),
		signatureAndHashes:  allSignatureAndHashAlgorithms,
	}

	c.writeRecord(recordTypeHandshake, hello.marshal())

	msg, err := c.readHandshake()
	if err != nil {
		return
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return
	}
	cipherID, version = serverHello.cipherSuite, serverHello.vers
	return
}
