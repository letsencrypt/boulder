// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// To test against a Boulder running on localhost in test mode:
// cd boulder/test/js
// npm install
// js test.js
//
// To test against a live or demo Boulder, edit this file to change
// newRegistrationURL, then run:
// sudo js test.js.

"use strict";

var colors = require("colors");
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

var cliOptions = cli.parse({
  // To test against the demo instance, pass --newReg "https://www.letsencrypt-demo.org/acme/new-reg"
  // To get a cert from the demo instance, you must be publicly reachable on
  // port 443 under the DNS name you are trying to get, and run test.js as root.
  newReg:  ["new-reg", "New Registration URL", "string", "http://localhost:4000/acme/new-reg"],
  certKeyFile:  ["certKey", "File for cert key (created if not exists)", "path", "cert-key.pem"],
  certFile:  ["cert", "Path to output certificate (DER format)", "path", "cert.pem"],
  email:  ["email", "Email address", "string", null],
  agreeTerms:  ["agree", "Agree to terms of service", "boolean", null],
  domain:  ["domain", "Domain name for which to request a certificate", "string", null],
});

var state = {
  certPrivateKey: null,
  accountPrivateKey: null,

  newRegistrationURL: cliOptions.newReg,
  registrationURL: "",

  termsRequired: false,
  termsAgreed: null,
  termsURL: null,

  domain: cliOptions.domain,

  newAuthorizationURL: "",
  authorizationURL: "",
  responseURL: "",
  path: "",
  retryDelay: 1000,

  newCertificateURL: "",
  certificateURL: "",
  certFile: cliOptions.certFile,
  keyFile: cliOptions.certKeyFile,
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

function post(url, body, callback) {
  var payload = JSON.stringify(body, null, 2);
  var jws = crypto.generateSignature(state.accountPrivateKey, new Buffer(payload));
  var signed = JSON.stringify(jws, null, 2);

  console.log('Posting to', url, ':');
  console.log(signed.green);
  console.log('Payload:')
  console.log(payload.blue);
  var req = request.post({
    url: url,
    encoding: null // Return body as buffer, needed for certificate response
    }, function(error, response, body) {
    // Don't print non-ASCII characters (like DER-encoded cert) to the terminal
    if (body && !body.toString().match(/[^\x00-\x7F]/)) {
      try {
        var parsed = JSON.parse(body);
        console.log(JSON.stringify(parsed, null, 2).cyan);
      } catch (e) {
        console.log(body.toString().cyan);
      }
    }
    callback(error, response, body)
  });
  req.on('response', function(response) {
    Object.keys(response.headers).forEach(function(key) {
      var value = response.headers[key];
      var upcased = key.charAt(0).toUpperCase() + key.slice(1);
      console.log((upcased + ": " + value).yellow)
    });
    console.log()
  })
  req.write(signed)
  req.end();
  return req;
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
  makeKeyPair();
}

function makeKeyPair() {
  console.log("Generating cert key pair...");
  child_process.exec("openssl req -newkey rsa:2048 -keyout " + state.keyFile + " -days 3650 -subj /CN=foo -nodes -x509 -out temp-cert.pem", function (error, stdout, stderr) {
    if (error) {
      console.log(error);
      process.exit(1);
    }
    state.certPrivateKey = crypto.importPemPrivateKey(fs.readFileSync(state.keyFile));

    console.log();
    makeAccountKeyPair()
  });
}

function makeAccountKeyPair(answers) {
  console.log("Generating account key pair...");
  child_process.exec("openssl genrsa -out account-key.pem 2048", function (error, stdout, stderr) {
    if (error) {
      console.log(error);
      process.exit(1);
    }
    state.accountPrivateKey = crypto.importPemPrivateKey(fs.readFileSync("account-key.pem"));

    console.log();
    if (cliOptions.email) {
      register({email: cliOptions.email});
    } else {
      inquirer.prompt(questions.email, register)
    }
  });
}

function register(answers) {
  var email = answers.email;

  // Register public key
  post(state.newRegistrationURL, {
    contact: [ "mailto:" + email ]
  }, getTerms);
}

function getTerms(err, resp) {
  if (err || Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Registration request failed:" + err);
    process.exit(1);
  }

  var links = parseLink(resp.headers["link"]);
  if (!links || !("next" in links)) {
    console.log("The server did not provide information to proceed");
    process.exit(1);
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

  if (!cliOptions.agreeTerms) {
    inquirer.prompt(questions.terms, sendAgreement);
  } else {
    sendAgreement({terms: true});
  }
}

function sendAgreement(answers) {
  state.termsAgreed = answers.terms;

  if (state.termsRequired && !state.termsAgreed) {
    console.log("Sorry, can't proceed if you don't agree.");
    process.exit(1);
  }

  console.log("Posting agreement to: " + state.registrationURL)

  state.registration = {
    agreement: state.termsURL
  }
  post(state.registrationURL, state.registration,
    function(err, resp, body) {
      if (err || Math.floor(resp.statusCode / 100) != 2) {
        console.log(body);
        console.log("error: " + err);
        console.log("Couldn't POST agreement back to server, aborting.");
        process.exit(1);
      } else {
        if (!state.domain) {
          inquirer.prompt(questions.domain, getChallenges);
        } else {
          getChallenges({domain: state.domain});
        }
      }
    });
}

function getChallenges(answers) {
  state.domain = answers.domain;

  // Register public key
  post(state.newAuthorizationURL, {
    identifier: {
      type: "dns",
      value: state.domain
    }
  }, getReadyToValidate);
}

function getReadyToValidate(err, resp, body) {
  if (err || Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Authorization request failed with code " + resp.statusCode)
    process.exit(1);
  }

  var links = parseLink(resp.headers["link"]);
  if (!links || !("next" in links)) {
    console.log("The server did not provide information to proceed");
    process.exit(1);
  }

  state.authorizationURL = resp.headers["location"];
  state.newCertificateURL = links["next"];

  var authz = JSON.parse(body);

  var simpleHttps = authz.challenges.filter(function(x) { return x.type == "simpleHttps"; });
  if (simpleHttps.length == 0) {
    console.log("The server didn't offer any challenges we can handle.");
    process.exit(1);
  }

  var challenge = simpleHttps[0];
  var path = crypto.randomString(8) + ".txt";
  var challengePath = ".well-known/acme-challenge/" + path;
  state.responseURL = challenge["uri"];
  state.path = path;

  // For local, test-mode validation
  function httpResponder(req, response) {
    console.log("\nGot request for", req.url);
    var host = req.headers["host"];
    if ((host === state.domain || /localhost/.test(state.newRegistrationURL)) &&
        req.method === "GET" &&
        req.url == "/" + challengePath) {
      response.writeHead(200, {"Content-Type": "text/plain"});
      response.end(challenge.token);
    } else {
      console.log("Got invalid request for", req.method, host, req.url);
      response.writeHead(404, {"Content-Type": "text/plain"});
      response.end("");
    }
  }
  if (/localhost/.test(state.newRegistrationURL)) {
    var httpServer = http.createServer(httpResponder)
    httpServer.listen(5001)
  } else {
    var httpServer = https.createServer({
      cert: fs.readFileSync("temp-cert.pem"),
      key: fs.readFileSync(state.keyFile) 
    }, httpResponder)
    httpServer.listen(443)
  }

  cli.spinner("Validating domain");
  post(state.responseURL, {
    path: state.path
  }, ensureValidation);
}

function ensureValidation(err, resp, body) {
  if (Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Authorization status request failed with code " + resp.statusCode)
    process.exit(1);
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
    process.exit(1);
  } else {
    console.log("The CA returned an authorization in an unexpected state");
    console.log(JSON.stringify(authz, null, "  "));
    process.exit(1);
  }
}

function getCertificate() {
  cli.spinner("Requesting certificate");
  var csr = crypto.generateCSR(state.certPrivateKey, state.domain);
  post(state.newCertificateURL, {
    csr: csr,
    authorizations: [ state.authorizationURL ]
  }, downloadCertificate);
}

function downloadCertificate(err, resp, body) {
  if (err || Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Certificate request failed with code " + resp.statusCode);
    console.log(body.toString());
    process.exit(1);
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
    if (err) {
      console.log("Error: Failed to fetch certificate from", certURL, ":", err);
      process.exit(1);
    }
    if (res.statusCode !== 200) {
      console.log("Error: Failed to fetch certificate from", certURL, ":", res.statusCode, res.body.toString());
  fs.writeFileSync(state.certFile, state.certificate);
      process.exit(1);
    }
    if (body.toString() !== state.certificate.toString()) {
      console.log("Error: cert at", certURL, "did not match returned cert.");
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

