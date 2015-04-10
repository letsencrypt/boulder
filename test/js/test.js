// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

"use strict";

var inquirer = require("inquirer");
var cli = require("cli");
var http = require('http');
var fs = require('fs');
var url = require('url');
var util = require("./acme-util");
var crypto = require("./crypto-util");

var questions = {
  email: [{
    type: "input",
    name: "email",
    message: "Please enter your email address (for recovery purposes)",
    validate: function(value) {
      var pass = value.match(/[\w.+-]+@[\w.-]+/i);
      if (pass) {
        return true;
      } else {
        return "Please enter a valid email address";
      }
    }
  }],

  terms: [{
    type: "confirm",
    name: "terms",
    message: "Do you agree to these terms?",
    default: false,
  }],

  domain: [{
    type: "input",
    name: "domain",
    message: "Please enter the domain name for the certificate",
    validate: function(value) {
      var pass = value.match(/[\w.-]+/i);
      if (pass) {
        return true;
      } else {
        return "Please enter a valid domain name";
      }
    }
  }],

  readyToValidate: [{
    type: "input",
    name: "noop",
    message: "Press enter to when you're ready to proceed",
  }],

  files: [{
    type: "input",
    name: "keyFile",
    message: "Name for key file",
    default: "key.pem"
  },{
    type: "input",
    name: "certFile",
    message: "Name for certificate file",
    default: "cert.pem"
  }],
};

var state = {
  keyPairBits: 512,
  keyPair: null,

  newRegistrationURL: "http://localhost:4000/acme/new-reg",
  registrationURL: "",

  termsRequired: false,
  termsAgreed: false,
  termsURL: null,

  domain: null,

  newAuthorizationURL: "",
  authorizationURL: "",
  responseURL: "",
  path: "",
  retryDelay: 1000,

  newCertificateURL: "",
  certificateURL: "",
};

function parseLink(link) {
  try {
    // NB: Takes last among links with the same "rel" value
    var links = link.split(',').map(function(link) {
      var parts = link.trim().split(";");
      var url = parts.shift().replace(/[<>]/g, "");
      var info = parts.reduce(function(acc, p) {
        var m = p.trim().match(/(.+) *= *"(.+)"/);
        if (m) acc[m[1]] = m[2];
        return acc
      }, {});
      info["url"] = url;
      return info;
    }).reduce(function(acc, link) {
      if ("rel" in link) {
        acc[link["rel"]] = link["url"]
      }
      return acc;
    }, {});
    return links;
  } catch (e) {
    return null;
  }
}

/*

The asynchronous nature of node.js libraries makes the control flow a
little hard to follow here, but it pretty much goes straight down the
page, with detours through the `inquirer` and `http` libraries.

main
  |
register
  |
getTerms
  | \
  |  getAgreement
  |  |
  |  sendAgreement
  | /
getDomain
  |
getChallenges
  |
getReadyToValidate
  |
sendResponse
  |
ensureValidation
  |
getCertificate
  |
downloadCertificate
  |
saveFiles


*/

function main() {
  console.log("Generating key pair...");
  state.keyPair = crypto.generateKeyPair(state.keyPairBits);
  console.log();
  inquirer.prompt(questions.email, register)
}

function register(answers) {
  var email = answers.email;

  // Register public key
  state.registration = {
    contact: [ "mailto:" + email ]
  }
  var registerMessage = JSON.stringify(state.registration);
  var jws = crypto.generateSignature(state.keyPair, new Buffer(registerMessage));
  var payload = JSON.stringify(jws);

  var options = url.parse(state.newRegistrationURL);
  options.method = "POST";
  var req = http.request(options, getTerms);
  req.write(payload)
  req.end();
}

function getTerms(resp) {
  if (Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Registration request failed with code " + resp.statusCode);
    return;
  }

  var links = parseLink(resp.headers["link"]);
  if (!links || !("next" in links)) {
    console.log("The server did not provide information to proceed");
    return
  }

  state.registrationURL = resp.headers["location"];
  state.newAuthorizationURL = links["next"];
  state.termsRequired = ("terms-of-service" in links);

  if (state.termsRequired) {
    state.termsURL = links["terms-of-service"];
    http.get(state.termsURL, getAgreement)
  } else {
    inquirer.prompt(questions.domain, getChallenges);
  }
}

function getAgreement(resp) {
  var body = "";
  resp.on("data", function(chunk) {
    body += chunk;
  });
  resp.on("end", function(chunk) {
    if (chunk) { body += chunk; }

    // TODO: Check content-type
    console.log("The CA requires your agreement to terms (not supported).");
    console.log();
    console.log(body);
    console.log();

    inquirer.prompt(questions.terms, sendAgreement);
  });
}

function sendAgreement(answers) {
  state.termsAgreed = answers.terms;

  if (state.termsRequired && !state.termsAgreed) {
    console.log("Sorry, can't proceed if you don't agree.");
    process.exit(1);
  }

  state.registration.agreement = state.termsURL;
  var registerMessage = JSON.stringify(state.registration);
  var jws = crypto.generateSignature(state.keyPair, new Buffer(registerMessage));
  var payload = JSON.stringify(jws);

  console.log("Posting agreement to: " + state.registrationURL)
  var options = url.parse(state.registrationURL);
  options.method = "POST";
  var req = http.request(options, function(resp) {
    var body = "";
    resp.on("data", function(chunk) { body += chunk; });
    resp.on("end", function() {
      if (Math.floor(resp.statusCode / 100) != 2) {
        // Non-2XX response
        console.log("Couldn't POST agreement back to server, aborting.");
        console.log("Code: "+ resp.statusCode);
        console.log(body);
        process.exit(1);
      }
    });

    inquirer.prompt(questions.domain, getChallenges);
  });
  req.write(payload)
  req.end();
}

function getChallenges(answers) {
  state.domain = answers.domain;

  // Register public key
  var authzMessage = JSON.stringify({
    identifier: {
      type: "dns",
      value: state.domain
    }
  });
  var jws = crypto.generateSignature(state.keyPair, new Buffer(authzMessage));
  var payload = JSON.stringify(jws);

  var options = url.parse(state.newAuthorizationURL);
  options.method = "POST";
  var req = http.request(options, getReadyToValidate);
  req.write(payload)
  req.end();
}

function getReadyToValidate(resp) {
  if (Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Authorization request failed with code " + resp.statusCode)
    return;
  }

  var links = parseLink(resp.headers["link"]);
  if (!links || !("next" in links)) {
    console.log("The server did not provide information to proceed");
    return
  }

  state.authorizationURL = resp.headers["location"];
  state.newCertificateURL = links["next"];

  var body = ""
  resp.on('data', function(chunk) {
    body += chunk;
  });
  resp.on('end', function(chunk) {
    if (chunk) { body += chunk; }

    var authz = JSON.parse(body);

    var simpleHttps = authz.challenges.filter(function(x) { return x.type == "simpleHttps"; });
    if (simpleHttps.length == 0) {
      console.log("The server didn't offer any challenges we can handle.");
      return;
    }

    var challenge = simpleHttps[0];
    var path = crypto.randomString(8) + ".txt";
    fs.writeFileSync(path, challenge.token);
    state.responseURL = challenge["uri"];
    state.path = path;

    console.log();
    console.log("To validate that you own "+ state.domain +", the CA has\n" +
                "asked you to provision a file on your server.  I've saved\n" +
                "the file here for you.\n");
    console.log("  File: " + path);
    console.log("  URL:  http://"+ state.domain +"/.well-known/acme-challenge/"+ path);
    console.log();

    // To do this locally (boulder connects to port 5001)
    // > mkdir -p .well-known/acme-challenge/
    // > mv $CHALLENGE_FILE ./well-known/acme-challenge/
    // > python -m SimpleHTTPServer 5001

    inquirer.prompt(questions.readyToValidate, sendResponse);
  });
}

function sendResponse() {
  var responseMessage = JSON.stringify({
    path: state.path
  });
  var jws = crypto.generateSignature(state.keyPair, new Buffer(responseMessage));
  var payload = JSON.stringify(jws);

  cli.spinner("Validating domain");

  var options = url.parse(state.responseURL);
  options.method = "POST";
  var req = http.request(options, ensureValidation);
  req.write(payload)
  req.end();
}

function ensureValidation(resp) {
  if (Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Authorization status request failed with code " + resp.statusCode)
    return;
  }

  var body = "";
  resp.on('data', function(chunk) {
    body += chunk;
  });
  resp.on('end', function(chunk) {
    if (chunk) { body += chunk; }

    var authz = JSON.parse(body);

    if (authz.status == "pending") {
      setTimeout(function() {
        http.get(state.authorizationURL, ensureValidation);
      }, state.retryDelay);
    } else if (authz.status == "valid") {
      cli.spinner("Validating domain ... done", true);
      console.log();
      getCertificate();
    } else if (authz.status == "invalid") {
      console.log("The CA was unable to validate the file you provisioned:"  + authz);
      return;
    } else {
      console.log("The CA returned an authorization in an unexpected state");
      console.log(JSON.stringify(authz, null, "  "));
      return;
    }
  });
}

function getCertificate() {
  var csr = crypto.generateCSR(state.keyPair, state.domain);

  var certificateMessage = JSON.stringify({
    csr: csr,
    authorizations: [ state.authorizationURL ]
  });
  var jws = crypto.generateSignature(state.keyPair, new Buffer(certificateMessage));
  var payload = JSON.stringify(jws);

  cli.spinner("Requesting certificate");

  var options = url.parse(state.newCertificateURL);
  options.method = "POST";
  var req = http.request(options, downloadCertificate);
  req.write(payload)
  req.end();
}

function downloadCertificate(resp) {
  var chunks = [];
  resp.on('data', function(chunk) {
    chunks.push(chunk);
  });
  resp.on('end', function(chunk) {
    if (chunk) { chunks.push(chunk); }
    var body = Buffer.concat(chunks);

    if (Math.floor(resp.statusCode / 100) != 2) {
      // Non-2XX response
      console.log("Certificate request failed with code " + resp.statusCode);
      console.log(body.toString());
      return;
    }

    cli.spinner("Requesting certificate ... done", true);
    console.log();
    var certB64 = util.b64enc(body);

    state.certificate = certB64;
    inquirer.prompt(questions.files, saveFiles);
  });
}

function saveFiles(answers) {
  var keyPEM = crypto.privateKeyToPem(state.keyPair.privateKey);
  fs.writeFileSync(answers.keyFile, keyPEM);

  var certPEM = crypto.certificateToPem(state.certificate);
  fs.writeFileSync(answers.certFile, certPEM);

  console.log("Done!")
  console.log("To try it out:");
  console.log("openssl s_server -accept 8080 -www -key "+
              answers.keyFile +" -cert "+ answers.certFile);

  // XXX: Explicitly exit, since something's tenacious here
  process.exit(0);
}


// BEGIN
main();

