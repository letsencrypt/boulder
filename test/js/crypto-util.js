var crypto = require("crypto");
var forge = require("node-forge");
var util = require("./acme-util.js");

var TOKEN_SIZE = 16;
var NONCE_SIZE = 16;

function bytesToBuffer(bytes) {
  return new Buffer(forge.util.bytesToHex(bytes), "hex");
}

function bufferToBytes(buf) {
  return forge.util.hexToBytes(buf.toString("hex"));
}

function bytesToBase64(bytes) {
  return util.b64enc(bytesToBuffer(bytes));
}

function base64ToBytes(base64) {
  return bufferToBytes(util.b64dec(base64));
}

function bnToBase64(bn) {
  var hex = bn.toString(16);
  if (hex.length % 2 == 1) { hex = "0" + hex; }
  return util.b64enc(new Buffer(hex, "hex"));
}

function base64ToBn(base64) {
  return new forge.jsbn.BigInteger(util.b64dec(base64).toString("hex"), 16);
}

function importPrivateKey(privateKey) {
  return forge.pki.rsa.setPrivateKey(
             base64ToBn(privateKey.n),
             base64ToBn(privateKey.e), base64ToBn(privateKey.d),
             base64ToBn(privateKey.p), base64ToBn(privateKey.q),
             base64ToBn(privateKey.dp),base64ToBn(privateKey.dq),
             base64ToBn(privateKey.qi));
}

function importPublicKey(publicKey) {
  return forge.pki.rsa.setPublicKey(
             base64ToBn(publicKey.n),
             base64ToBn(publicKey.e));
}

function exportPrivateKey(privateKey) {
  return {
    "kty": "RSA",
    "n": bnToBase64(privateKey.n),
    "e": bnToBase64(privateKey.e),
    "d": bnToBase64(privateKey.d),
    "p": bnToBase64(privateKey.p),
    "q": bnToBase64(privateKey.q),
    "dp": bnToBase64(privateKey.dP),
    "dq": bnToBase64(privateKey.dQ),
    "qi": bnToBase64(privateKey.qInv)
  };
}

function exportPublicKey(publicKey) {
  return {
    "kty": "RSA",
    "n": bnToBase64(publicKey.n),
    "e": bnToBase64(publicKey.e)
  };
}

// A note on formats:
// * Keys are always represented as JWKs
// * Signature objects are in ACME format
// * Certs and CSRs are base64-encoded
module.exports = {
   ///// RANDOM STRINGS

  randomString: function(nBytes) {
    return bytesToBase64(forge.random.getBytesSync(nBytes));
  },

  randomSerialNumber: function() {
    return forge.util.bytesToHex(forge.random.getBytesSync(4));
  },

  newToken: function() {
    return this.randomString(TOKEN_SIZE);
  },

  ///// SHA-256

  sha256: function(buf) {
    return crypto.createHash('sha256').update(buf).digest('hex');
  },

  ///// KEY PAIR MANAGEMENT

  generateKeyPair: function(bits) {
    var keyPair = forge.pki.rsa.generateKeyPair({bits: bits, e: 0x10001});
    return {
      privateKey: exportPrivateKey(keyPair.privateKey),
      publicKey: exportPublicKey(keyPair.publicKey)
    };
  },

  importPemPrivateKey: function(pem) {
    var key = forge.pki.privateKeyFromPem(pem);
    return {
      privateKey: exportPrivateKey(key),
      publicKey: exportPublicKey(key)
    };
  },

  importPemCertificate: function(pem) {
    return forge.pki.certificateFromPem(pem);
  },

  privateKeyToPem: function(privateKey) {
    var priv = importPrivateKey(privateKey);
    return forge.pki.privateKeyToPem(priv);
  },

  certificateToPem: function(certificate) {
    var derCert = base64ToBytes(certificate);
    var cert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(derCert));
    return forge.pki.certificateToPem(cert);
  },

  certificateRequestToPem: function(csr) {
    var derReq = base64ToBytes(csr);
    var c = forge.pki.certificateFromAsn1(forge.asn1.fromDer(derReq));
    return forge.pki.certificateRequestToPem(c);
  },

  thumbprint: function(publicKey) {
    // Only handling RSA keys
    input = bytesToBuffer('{"e":"'+ publicKey.e + '","kty":"RSA","n":"'+ publicKey.n +'"}');
    return util.b64enc(crypto.createHash('sha256').update(input).digest());
  },

  ///// SIGNATURE GENERATION / VERIFICATION

  generateSignature: function(keyPair, payload, nonce) {
    var privateKey = importPrivateKey(keyPair.privateKey);

    // Compute JWS signature
    var protectedHeader = "";
    if (nonce) {
      protectedHeader = JSON.stringify({nonce: nonce});
    }
    var protected64 = util.b64enc(new Buffer(protectedHeader));
    var payload64 = util.b64enc(payload);
    var signatureInputBuf = new Buffer(protected64 + "." + payload64);
    var signatureInput = bufferToBytes(signatureInputBuf);
    var md = forge.md.sha256.create();
    md.update(signatureInput);
    var sig = privateKey.sign(md);

    return {
      header: {
        alg: "RS256",
        jwk: keyPair.publicKey,
      },
      protected: protected64,
      payload: payload64,
      signature: util.b64enc(bytesToBuffer(sig)),
    }
  },

  verifySignature: function(jws) {
    if (jws.protected) {
      if (!jws.header) {
        jws.header = {};
      }

      try {
        console.log(jws.protected);
        var protectedJSON = util.b64dec(jws.protected).toString();
        console.log(protectedJSON);
        var protectedObj = JSON.parse(protectedJSON);
        for (key in protectedObj) {
          jws.header[key] = protectedObj[key];
        }
      } catch (e) {
        console.log("error unmarshaling json: "+e)
        return false;
      }
    }

    // Assumes validSignature(sig)
    if (!jws.header.jwk || (jws.header.jwk.kty != "RSA")) {
      // Unsupported key type
      console.log("Unsupported key type");
      return false;
    } else if (!jws.header.alg || !jws.header.alg.match(/^RS/)) {
      // Unsupported algorithm
      console.log("Unsupported alg: "+jws.header.alg);
      return false;
    }

    // Compute signature input
    var protected64 = (jws.protected)? jws.protected : "";
    var payload64 = (jws.payload)? jws.payload : "";
    var signatureInputBuf = new Buffer(protected64 + "." + payload64);
    var signatureInput = bufferToBytes(signatureInputBuf);

    // Compute message digest
    var md;
    switch (jws.header.alg) {
      case "RS1":   md = forge.md.sha1.create(); break;
      case "RS256": md = forge.md.sha256.create(); break;
      case "RS384": md = forge.md.sha384.create(); break;
      case "RS512": md = forge.md.sha512.create(); break;
      default: return false; // Unsupported algorithm
    }
    md.update(signatureInput);

    // Import the key and signature
    var publicKey = importPublicKey(jws.header.jwk);
    var sig = bufferToBytes(util.b64dec(jws.signature));

    return publicKey.verify(md.digest().bytes(), sig);
  },

  ///// CSR GENERATION / VERIFICATION

  generateCSR: function(keyPair, names) {
    var privateKey = importPrivateKey(keyPair.privateKey);
    var publicKey = importPublicKey(keyPair.publicKey);

    // Create and sign the CSR
    var csr = forge.pki.createCertificationRequest();
    csr.publicKey = publicKey;
    csr.setSubject([{ name: 'commonName', value: names[0] }]);

    var sans = [];
    for (i in names) {
      sans.push({ type: 2, value: names[i] });
    }
    csr.setAttributes([{
      name: 'extensionRequest',
      extensions: [{name: 'subjectAltName', altNames: sans}]
    }]);

    csr.sign(privateKey, forge.md.sha256.create());

    // Convert CSR -> DER -> Base64
    var der = forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr));
    return util.b64enc(bytesToBuffer(der));
  },

  verifiedCommonName: function(csr_b64) {
    var der = bufferToBytes(util.b64dec(csr_b64));
    var csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(der));

    if (!csr.verify()) {
      return false;
    }

    for (var i=0; i<csr.subject.attributes.length; ++i) {
      if (csr.subject.attributes[i].name == "commonName") {
        return csr.subject.attributes[i].value;
      }
    }
    return false;
  },

  ///// CERTIFICATE GENERATION

  // 'ca' parameter includes information about the CA
  // {
  //   distinguishedName: /* forge-formatted DN */
  //   keyPair: {
  //     publicKey: /* JWK */
  //     privateKey: /* JWK */
  //   }
  // }
  generateCertificate: function(ca, serialNumber, csr_b64) {
    var der = bufferToBytes(util.b64dec(csr_b64));
    var csr = forge.pki.certificationRequestFromAsn1(forge.asn1.fromDer(der));

    // Extract the public key and common name
    var publicKey = csr.publicKey;
    var commonName = null;
    for (var i=0; i<csr.subject.attributes.length; ++i) {
      if (csr.subject.attributes[i].name == "commonName") {
        commonName = csr.subject.attributes[i].value;
        break;
      }
    }
    if (!commonName) { return false; }

    // Create the certificate
    var cert = forge.pki.createCertificate();
    cert.publicKey = publicKey;
    cert.serialNumber = serialNumber;

    // 1-year validity
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    cert.setSubject([{ name: "commonName", value: commonName }]);
    cert.setIssuer(ca.distinguishedName);
    cert.setExtensions([
      { name: "basicConstraints", cA: false },
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
      { name: "extKeyUsage", serverAuth: true },
      { name: "subjectAltName", altNames: [{ type: 2, value: commonName }] }
    ]);

    // Import signing key and sign
    var privateKey = importPrivateKey(ca.keyPair.privateKey);
    cert.sign(privateKey);

    // Return base64-encoded DER
    var der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
    return bytesToBuffer(der);
  },

  generateDvsniCertificate: function(keyPair, nonceName, zName) {
    var cert = forge.pki.createCertificate();
    cert.publicKey = importPublicKey(keyPair.publicKey);
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
    cert.setSubject([{ name: "commonName", value: nonceName }]);
    cert.setIssuer([{ name: "commonName", value: nonceName }]);
    cert.setExtensions([
      { name: "basicConstraints", cA: false },
      { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
      { name: "extKeyUsage", serverAuth: true },
      { name: "subjectAltName", altNames: [
          { type: 2, value: nonceName },
          { type: 2, value: zName }
      ]}
    ]);
    cert.sign(importPrivateKey(keyPair.privateKey));

    // Return base64-encoded DER, as above
    var der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert));
    return util.b64enc(bytesToBuffer(der));
  },

  ///// TLS CONTEXT GENERATION

  createContext: function(keyPair, cert) {
    var privateKey = importPrivateKey(keyPair.privateKey);
    var derCert = bufferToBytes(util.b64dec(cert));
    var realCert = forge.pki.certificateFromAsn1(forge.asn1.fromDer(derCert));
    return crypto.createCredentials({
      key: forge.pki.privateKeyToPem(privateKey),
      cert: forge.pki.certificateToPem(realCert)
    }).context;
  }
};
