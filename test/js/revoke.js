// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// To revoke a certificate against a local Boulder:
// js revoke.js cert.pem key.pem

'use strict';

var crypto = require('./crypto-util');
var util = require('./acme-util');
var forge = require('node-forge');
var fs = require('fs');
var request = require('request');

function main() {
  if (process.argv.length != 5) {
    console.log('Usage: js revoke.js cert.der key.pem REVOKE_URL');
    process.exit(1);
  }
  var key = crypto.importPemPrivateKey(fs.readFileSync(process.argv[3]));
  var certDER = fs.readFileSync(process.argv[2])
  var revokeUrl = process.argv[4];
  var certDERB64URL = util.b64enc(new Buffer(certDER))
  var revokeMessage = JSON.stringify({
    // For some reason forge adds an extra, incorrect '00' at the front of the
    // serial number.
    certificate: certDERB64URL
  });
  console.log('Requesting revocation:', revokeMessage)
  var jws = crypto.generateSignature(key, new Buffer(revokeMessage));
  var req = request.post(revokeUrl, function(err, resp) {
    if (err) {
      console.log('Error: ', err);
    }
    console.log(resp.statusCode);
    console.log(resp.headers);
    console.log(resp.body);
  });
  var payload = JSON.stringify(jws);
  console.log(payload);
  req.write(payload);
  req.end();
}
main();
