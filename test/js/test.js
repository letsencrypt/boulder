// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

"use strict";

var cli = require("cli");
var crypto = require("./crypto-util");
var child_process = require('child_process');
var fs = require('fs');
var http = require('http');
var https = require('https');
var inquirer = require("inquirer");
var request = require('request');
var url = require('url');
var util = require("./acme-util");

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
    default: true,
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
    default: "cert.der"
  }],
};

var state = {
  keyPair: null,

  //newRegistrationURL: "https://www.letsencrypt-demo.org/acme/new-reg",
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
  certFile: "",
  keyFile: ""
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
  inquirer.prompt(questions.files, makeKeyPair);
}

function makeKeyPair(answers) {
  state.certFile = answers.certFile;
  state.keyFile = answers.keyFile;
  console.log("Generating key pair...");
  child_process.exec("openssl req -newkey", state.keyFile, "-days 3650 -subj /CN=blah -nodes -out temp-cert.pem");
  state.keyPair = crypto.importPemPrivateKey(fs.readFileSync(state.keyFile));

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

  var req = request.post(state.newRegistrationURL, {}, getTerms);
  req.write(payload)
  req.end();
}

function getTerms(err, resp) {
  if (err || Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Registration request failed:" + err);
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
    console.log(state.termsURL);
    request.get(state.termsURL, getAgreement)
  } else {
    inquirer.prompt(questions.domain, getChallenges);
  }
}

function getAgreement(err, resp, body) {
  if (err) {
    console.log("getAgreement error:", err);
    process.exit(1);
  }
  // TODO: Check content-type
  console.log("The CA requires your agreement to terms.");
  console.log();
  console.log(body);
  console.log();

  inquirer.prompt(questions.terms, sendAgreement);
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
  var req = request(state.registrationURL, {}, function(err, resp, body) {
    if (err) {
      console.log("Couldn't POST agreement back to server, aborting.");
      console.log("error: " + err);
      console.log(body);
      process.exit(1);
    }

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

  var req = request.post(state.newAuthorizationURL, {}, getReadyToValidate);
  req.write(payload)
  req.end();
}

function getReadyToValidate(err, resp, body) {
  if (err || Math.floor(resp.statusCode / 100) != 2) {
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

  var authz = JSON.parse(body);

  var simpleHttps = authz.challenges.filter(function(x) { return x.type == "simpleHttps"; });
  if (simpleHttps.length == 0) {
    console.log("The server didn't offer any challenges we can handle.");
    return;
  }

  var challenge = simpleHttps[0];
  var path = crypto.randomString(8) + ".txt";
  var challengePath = ".well-known/acme-challenge/" + path;
  fs.writeFileSync(challengePath, challenge.token);
  state.responseURL = challenge["uri"];
  state.path = path;

  // For local, test-mode validation
  function httpResponder(request, response) {
    console.log("Got request for", request.url);
    var host = request.headers["host"];
    if (host === state.domain &&
        request.method === "GET" &&
        request.url == "/" + challengePath) {
      response.writeHead(200, {"Content-Type": "text/plain"});
      response.end(challenge.token);
    } else {
      console.log("Got invalid request for", request.method, host, request.url);
      response.writeHead(404, {"Content-Type": "text/plain"});
      response.end("");
    }
  };
  if (/localhost/.test(state.newRegistrationURL)) {
    var httpServer = http.createServer(httpResponder)
    httpServer.listen(5001)
  } else {
    var httpServer = https.createServer({
      cert: fs.readFileSync("temp-cert.pem"),
      key: fs.readFileSync(state.keyFile) 
    })
    httpServer.listen(443)
  }

  inquirer.prompt(questions.readyToValidate, sendResponse);
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
  var req = request.post(state.responseURL, {}, ensureValidation);
  req.write(payload)
  req.end();
}

function ensureValidation(err, resp, body) {
  if (Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Authorization status request failed with code " + resp.statusCode)
    return;
  }

  var authz = JSON.parse(body);

  if (authz.status == "pending") {
    setTimeout(function() {
      request.get(state.authorizationURL, {}, ensureValidation);
    }, state.retryDelay);
  } else if (authz.status == "valid") {
    cli.spinner("Validating domain ... done", true);
    console.log();
    getCertificate();
  } else if (authz.status == "invalid") {
    console.log("The CA was unable to validate the file you provisioned:"  + body);
    return;
  } else {
    console.log("The CA returned an authorization in an unexpected state");
    console.log(JSON.stringify(authz, null, "  "));
    return;
  }
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

  var req = request.post({
    url: state.newCertificateURL,
    encoding: null // Return body as buffer.
  }, downloadCertificate);
  req.write(payload)
  req.end();
}

function downloadCertificate(err, resp, body) {
  if (err || Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Certificate request failed with code " + resp.statusCode);
    console.log(body.toString());
    return;
  }

  cli.spinner("Requesting certificate ... done", true);
  console.log();

  state.certificate = body;
  console.log()
  var certURL = resp.headers['location'];
  request.get({
    url: certURL,
    encoding: null // Return body as buffer.
  }, function(err, res, body) {
    if (body.toString() !== state.certificate.toString()) {
      console.log("ERROR! Cert at", certURL, "did not match returned cert.");
    } else {
      console.log("Successfully verified cert at", certURL);
      saveFiles()
    }
  });
}

function saveFiles(answers) {
  fs.writeFileSync(state.certFile, state.certificate);

  console.log("Done!")
  console.log("To try it out:");
  console.log("openssl s_server -accept 8080 -www -certform der -key "+
              state.keyFile +" -cert "+ state.certFile);

  // XXX: Explicitly exit, since something's tenacious here
  process.exit(0);
}


// BEGIN
main();

