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
  var certFile = process.argv[2];
  console.log('Attempting to revoke', certFile);
  var key = crypto.importPemPrivateKey(fs.readFileSync(process.argv[3]));
  var certDER = fs.readFileSync(certFile)
  var revokeUrl = process.argv[4];
  var certDERB64URL = util.b64enc(new Buffer(certDER))
  var revokeMessage = JSON.stringify({
    resource: "revoke-cert",
    certificate: certDERB64URL
  });
  console.log('Requesting revocation:', revokeMessage)

  request.head(revokeUrl, function(error, response, body) {
    if (error) {
      console.log(error);
      process.exit(1);
    } else if (response.statusCode != 200) {
      console.log("Got non-200 response asking for nonce (non-fatal):", response.statusCode);
    }
    var nonce = response.headers["replay-nonce"];
    if (!nonce) {
      console.log("Server HEAD response did not include a replay nonce");
      process.exit(1);
    }

    var jws = crypto.generateSignature(key, new Buffer(revokeMessage), nonce);
    var payload = JSON.stringify(jws);

    var req = request.post(revokeUrl, function(error, response) {
      if (error || Math.floor(response.statusCode / 100) != 2) {
        console.log('Error: ', error);
        process.exit(1);
      } else {
        console.log("Revocation request successful.");
      }
    });
    req.write(payload);
    req.end();
  });
}
main();
