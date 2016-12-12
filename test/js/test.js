// To test against a Boulder running on localhost in test mode:
// cd boulder/test/js
// npm install
// js test.js
//
// To test against a live or demo Boulder, pass the argument
// --directory with the URL of the directory endpoint.

"use strict";

var colors = require("colors");
var cli = require("cli");
var cryptoUtil = require("./crypto-util");
var crypto = require("crypto");
var child_process = require('child_process');
var fs = require('fs');
var http = require('http');
var request = require('request');
var url = require('url');
var util = require("./acme-util");
var Acme = require("./acme");

var cliOptions = cli.parse({
  // To test against the demo instance, pass --directory "https://acme-staging.api.letsencrypt.org/acme/directory"
  // To get a cert from the demo instance, you must be publicly reachable on
  // port 443 under the DNS name you are trying to get, and run test.js as root.
  directory:  ["directory", "Directory URL", "string", "http://localhost:4000/directory"],
  certKeyFile:  ["certKey", "File for cert key (created if not exists)", "path", "cert-key.pem"],
  certFile:  ["cert", "Path to output certificate (DER format)", "path", "cert.pem"],
  email:  ["email", "Email address", "string", null],
  domains:  ["domains", "Domain name(s) for which to request a certificate (comma-separated)", "string", null],
  challType: ["challType", "Name of challenge type to use for validations", "string", "http-01"],
  abortStep: ["abort-step", "Stop the issuance after reaching a certain step", "string", null]
});

var state = {
  certPrivateKey: null,
  accountKeyPair: null,

  directoryURL: cliOptions.directory,
  newRegistrationURL: "",
  registrationURL: "",
  keyChangeURL: "",

  domains: cliOptions.domains && cliOptions.domains.replace(/\s/g, "").split(/[^\w.-]+/),
  validatedDomains: [],
  validAuthorizationURLs: [],

  // We will use this as a push/shift FIFO in post() and getNonce()
  nonces: [],

  newAuthorizationURL: "",
  authorizationURL: "",
  responseURL: "",
  path: "",
  retryDelay: 1000,

  newCertificateURL: "",
  certificateURL: "",
  certFile: cliOptions.certFile,
  keyFile: cliOptions.certKeyFile,
  nextTests: (process.env.BOULDER_CONFIG_DIR != undefined && process.env.BOULDER_CONFIG_DIR.endsWith("test/config-next")),
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

var post = function(url, body, callback) {
  return state.acme.post(url, body, callback);
}

/*

The asynchronous nature of node.js libraries makes the control flow a
little hard to follow here, but it pretty much goes straight down the
page.

main
  |
makeKeyPair
  |
populateURLs
  |
register
  |
getTerms
  |
sendAgreement
  |
rotateAccountKey
  |
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
deactivateAuthorization
  |
deactivateAccount
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
    state.certPrivateKey = cryptoUtil.importPemPrivateKey(fs.readFileSync(state.keyFile));

    console.log();
    makeAccountKeyPair("account-key.pem", populateURLs)
  });
}

function populateURLs() {
    request(state.directoryURL, function (err, resp, body) {
        if (err || resp.statusCode != 200) {
            console.log(body);
            console.log("Failed to retrieve directory, failing.");
            process.exit(1);
        }
        var directory = JSON.parse(body);
        if (directory['new-reg'] == "" || state.nextTests && directory['key-change'] == "") {
            console.log(body);
            console.log("Incomplete directory returned, failing.");
            process.exit(1);
        }
        state.newRegistrationURL = directory['new-reg'];
        state.keyChangeURL = directory['key-change'];

        register();
    });
}

function makeAccountKeyPair(keyName, callback) {
  console.log("Generating account key pair...");
    child_process.exec("openssl genrsa -out " + keyName + " 2048", function (error, stdout, stderr) {
        if (error) {
            console.log(error);
            process.exit(1);
        }

        state.accountKeyPair = cryptoUtil.importPemPrivateKey(fs.readFileSync(keyName));
        state.acme = new Acme(state.accountKeyPair);

        callback();
    });
}

function register() {
  var contact = [];
  if (cliOptions.email) {
    contact.push("mailto:" + cliOptions.email);
  }
  // Register public key
  post(state.newRegistrationURL, {
    resource: "new-reg",
    contact: contact
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

  sendAgreement(links["terms-of-service"]);
}

function sendAgreement(termsURL) {
  console.log("Posting agreement to: " + state.registrationURL)

  state.registration = {
    resource: "reg",
    agreement: termsURL
  }
  post(state.registrationURL, state.registration,
    function(err, resp, body) {
      if (err || Math.floor(resp.statusCode / 100) != 2) {
        console.log(body);
        console.log("error: " + err);
        console.log("Couldn't POST agreement back to server, aborting.");
        process.exit(1);
      } else {
          if (state.nextTests) {
              rotateAccountKey();
          } else {
              getChallenges({domain: state.domains.pop()});
          }
      }
    });
}

function rotateAccountKey() {
    // Make a new account key
    var oldAcme = state.acme;
    makeAccountKeyPair("new-account-key.pem", function() {
        var payload = JSON.stringify({
            newKey: state.acme.privateKey.publicKey,
            account: state.registrationURL,
        }, null, 2)
        var signed = cryptoUtil.generateSignature(state.acme.privateKey, new Buffer(payload), null);
        signed.resource = "key-change"
        oldAcme.post(state.keyChangeURL, signed, function(err, resp, body) {
            if (err || Math.floor(resp.statusCode / 100) != 2) {
                console.log(body);
                console.log("error: " + err);
                console.log("POST to /acme/key-change failed, aborting.");
                process.exit(1)
            }

            getChallenges({domain: state.domains.pop()});
        });
    });
}

function getChallenges(params) {
  state.domain = params.domain;

  // Register public key
  post(state.newAuthorizationURL, {
    resource: "new-authz",
    identifier: {
      type: "dns",
      value: state.domain,
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

  if (cliOptions.abortStep === "startChallenge") {
    console.log("authorization-url=" + state.authorizationURL);
    process.exit(0);
  }

  var challenges = authz.challenges.filter(function(x) { return x.type == cliOptions.challType; });
  if (challenges.length == 0) {
    console.log("The server didn't offer any challenges we can handle.");
    process.exit(1);
  }
  state.responseURL = challenges[0]["uri"];

  var validator;
  if (cliOptions.challType == "http-01") {
    validator = validateHttp01;
  } else if (cliOptions.challType == "dns-01") {
    validator = validateDns01;
  }
  validator(challenges[0]);
}

function validateDns01(challenge) {
  // Construct a key authorization for this token and key, and the
  // correct record name to store it
  var thumbprint = cryptoUtil.thumbprint(state.accountKeyPair.publicKey);
  var keyAuthorization = challenge.token + "." + thumbprint;
  var recordName = "_acme-challenge." + state.domain + ".";

  function txtCallback(err, resp, body) {
    if (err) {
      console.log("Updating dns-test-srv failed:", err);
      process.exit(1);
    } else if (Math.floor(resp.statusCode / 100) != 2) {
      // Non-2XX response
      console.log("Updating dns-test-srv failed with code", resp.statusCode);
      process.exit(1);
    }
    post(state.responseURL, {
      resource: "challenge",
      keyAuthorization: keyAuthorization,
    }, ensureValidation);
  }

  request.post({
    uri: "http://localhost:8055/set-txt",
    method: "POST",
    json: {
      "host": recordName,
      "value": util.b64enc(crypto.createHash('sha256').update(keyAuthorization).digest())
    }
  }, txtCallback);
}

function validateHttp01(challenge) {
  // Construct a key authorization for this token and key
  var thumbprint = cryptoUtil.thumbprint(state.accountKeyPair.publicKey);
  var keyAuthorization = challenge.token + "." + thumbprint;

  var challengePath = ".well-known/acme-challenge/" + challenge.token;
  state.path = challengePath;

  // For local, test-mode validation
  function httpResponder(req, response) {
    console.log("\nGot request for", req.url);
    var host = req.headers["host"];
    if ((host.split(/:/)[0] === state.domain || /localhost/.test(state.newRegistrationURL)) &&
        req.method === "GET" &&
        req.url == "/" + challengePath) {
      console.log("Providing key authorization:", keyAuthorization);
      response.writeHead(200, {"Content-Type": "application/json"});
      response.end(keyAuthorization);
    } else {
      console.log("Got invalid request for", req.method, host, req.url);
      response.writeHead(404, {"Content-Type": "text/plain"});
      response.end("");
    }
  }
  state.httpServer = http.createServer(httpResponder)
  if (/localhost/.test(state.newRegistrationURL)) {
    state.httpServer.listen(5002)
  } else {
    state.httpServer.listen(80)
  }

  cli.spinner("Validating domain");
  post(state.responseURL, {
    resource: "challenge",
    keyAuthorization: keyAuthorization,
  }, ensureValidation);
}

function ensureValidation(err, resp, body) {
  if (Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Authorization status request failed with code " + resp.statusCode)
    process.exit(1);
  }

  var authz = JSON.parse(body);

  if (authz.status != "pending" && state.httpServer != null) {
    state.httpServer.close();
  }

  if (authz.status == "pending") {
    setTimeout(function() {
      request.get(state.authorizationURL, {}, ensureValidation);
    }, state.retryDelay);
  } else if (authz.status == "valid") {
    cli.spinner("Validating domain ... done", true);
    console.log();
    state.validatedDomains.push(state.domain);
    state.validAuthorizationURLs.push(state.authorizationURL);

    console.log("have CLI domains: ");
    console.log(state.domains);
    if (state.domains.length > 0) {
      getChallenges({domain: state.domains.pop()});
    } else {
      getCertificate();
    }
  } else if (authz.status == "invalid") {
    console.log("The CA was unable to validate the file you provisioned:");
    console.log(JSON.stringify(authz.challenges, null, "  "));
    process.exit(1);
  } else {
    console.log("The CA returned an authorization in an unexpected state");
    console.log(JSON.stringify(authz, null, "  "));
    process.exit(1);
  }
}

function getCertificate() {
  cli.spinner("Requesting certificate");
  var csr = cryptoUtil.generateCSR(state.certPrivateKey, state.validatedDomains);
  post(state.newCertificateURL, {
    resource: "new-cert",
    csr: csr,
    authorizations: state.validAuthorizationURLs,
  }, downloadCertificate);
}

function downloadCertificate(err, resp, body) {
  if (err || Math.floor(resp.statusCode / 100) != 2) {
    // Non-2XX response
    console.log("Certificate request failed with error ", err);
    if (body) {
      console.log(body.toString());
    }
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
      if (state.nextTests) {
        deactivateAuthorization();
      } else {
        saveFiles();
      }
    }
  });
}

function deactivateAuthorization() {
    post(state.authorizationURL, {
        resource: "authz",
        status: "deactivated"
    }, function(err, resp, body) {
        if (err || resp.statusCode != 200) {
            console.log("error: " + err);
            console.log("Couldn't deactivate authorization")
            process.exit(1);
        }

        var authz = JSON.parse(body);
        if (authz.status != "deactivated") {
            console.log("Authorization wasn't properly deactivated");
            process.exit(1);
        }

        request.get(state.authorizationURL, function(err, resp, body) {
            if (err || resp.statusCode != 200) {
                console.log("Unable to retrieve deactivated authorization")
                process.exit(1);
            }

            var authz = JSON.parse(body);
            if (authz.status != "deactivated") {
                console.log("Authorization wasn't properly deactivated");
                process.exit(1);
            }

            deactivateAccount();
        });
    });
}

function deactivateAccount() {
    post(state.registrationURL, {
        resource: "reg",
        status: "deactivated"
    },
    function(err, resp, body) {
        if (err || Math.floor(resp.statusCode / 100) != 2) {
            console.log("error: " + err);
            process.exit(1);
        }

        // Test account is actually deactivated
        post(state.registrationURL, {resource:"reg"}, function(err, resp, body) {
            if (resp.statusCode != 403) {
                console.log("POST to registration URL after deactivating account didn't fail.")
                process.exit(1);
            }

            saveFiles();
        });
    });
}

function saveFiles() {
  fs.writeFileSync(state.certFile, state.certificate);

  console.log("Done!")
  console.log("Key:", state.keyFile);
  console.log("Cert:", state.certFile);
  console.log("Account Key: account-key.pem");

  // XXX: Explicitly exit, since something's tenacious here
  process.exit(0);
}

// BEGIN
main();

