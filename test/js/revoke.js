// To revoke a certificate against a local Boulder:
// js revoke.js cert.pem key.pem

'use strict';

var crypto = require('./crypto-util');
var util = require('./acme-util');
var forge = require('node-forge');
var fs = require('fs');
var request = require('request');
var Acme = require('./acme');

function main() {
  if (process.argv.length != 5) {
    console.log('Usage: js revoke.js cert.der key.pem REVOKE_URL');
    process.exit(1);
  }
  var certFile = process.argv[2];
  var key = crypto.importPemPrivateKey(fs.readFileSync(process.argv[3]));
  var acme = new Acme(key);
  var certDER = fs.readFileSync(certFile)
  if (certDER.toString().match(/-----BEGIN/)) {
    console.log('Got PEM, expected DER:', certFile);
    process.exit(1);
  }
  var revokeUrl = process.argv[4];
  var certDERB64URL = util.b64enc(new Buffer(certDER))
  console.log('Attempting to revoke', certFile);
  acme.post(revokeUrl, {
    resource: 'revoke-cert',
    certificate: certDERB64URL
  }, function(err, response, body) {
    if (!err && response.statusCode === 200) {
      console.log('Success');
    }
  });
}
main();
