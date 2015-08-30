"use strict";

var colors = require("colors");
var cryptoUtil = require("./crypto-util");
var request = require('request');
function Acme(privateKey) {
  this.privateKey = privateKey;
  this.nonces = [];
}

Acme.prototype.getNonce = function(url, callback) {
  var req = request.head({
    url: url,
  }, function(error, response, body) {
    if (error) {
      console.error(error);
      process.exit(1);
    }
    if (response && "replay-nonce" in response.headers) {
      console.log("Storing nonce: " + response.headers["replay-nonce"]);
      this.nonces.push(response.headers["replay-nonce"]);
      callback();
      return;
    }

    console.log("Failed to get nonce for request");
    process.exit(1);
  }.bind(this));
}

Acme.prototype.post = function(url, body, callback) {
  // Pre-flight with HEAD if we don't have a nonce
  if (this.nonces.length == 0) {
    this.getNonce(url, function() {
      this.post(url, body, callback);
    }.bind(this))
    return;
  }

  console.log("Using nonce: " + this.nonces[0]);
  var payload = JSON.stringify(body, null, 2);
  var jws = cryptoUtil.generateSignature(this.privateKey,
                                         new Buffer(payload),
                                         this.nonces.shift());
  var signed = JSON.stringify(jws, null, 2);

  console.log('Posting to', url, ':');
  console.log(signed.green);
  console.log('Payload:')
  console.log(payload.blue);
  var req = request.post({
    url: url,
    body: signed,
    // Return body as buffer, needed for certificate response
    encoding: null,
  }, function(error, response, body) {
    if (error) {
      console.error(error);
      process.exit(1);
    }
    if (response) {
      console.log(("HTTP/1.1 " + response.statusCode).yellow)
    }
    Object.keys(response.headers).forEach(function(key) {
      var value = response.headers[key];
      var upcased = key.charAt(0).toUpperCase() + key.slice(1);
      console.log((upcased + ": " + value).yellow)
    });
    console.log()

    // Don't print non-ASCII characters (like DER-encoded cert) to the terminal
    if (body && !body.toString().match(/[^\x00-\x7F]/)) {
      try {
        var parsed = JSON.parse(body);
        console.log(JSON.stringify(parsed, null, 2).cyan);
      } catch (e) {
        console.log(body.toString().cyan);
      }
    }

    // Remember the nonce provided by the server
    if ("replay-nonce" in response.headers) {
      console.log("Storing nonce: " + response.headers["replay-nonce"]);
      this.nonces.push(response.headers["replay-nonce"]);
    }

    callback(error, response, body)
  }.bind(this));
  req.on('response', function(response) {
  })
  return req;
}

module.exports = Acme;
