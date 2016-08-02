module.exports = {

  fromStandardB64: function(x) {
    return x.replace(/[+]/g, "-").replace(/\//g, "_").replace(/=/g,"");
  },

  toStandardB64: function(x) {
    var b64 = x.replace(/-/g, "+").replace(/_/g, "/").replace(/=/g, "");

    switch (b64.length % 4) {
      case 2: b64 += "=="; break;
      case 3: b64 += "="; break;
    }

    return b64;
  },

  b64enc: function(buffer) {
    return this.fromStandardB64(buffer.toString("base64"));
  },

  b64dec: function(str) {
    return new Buffer(this.toStandardB64(str), "base64");
  },

  isB64String: function(x) {
    return (typeof(x) == "string") && !x.match(/[^a-zA-Z0-9_-]/);
  },

  fieldsPresent: function(fields, object) {
    for (var i in fields) {
      if (!(fields[i] in object)) {
        return false;
      }
    }
    return true;
  },

  validSignature: function(sig) {
    return ((typeof(sig) == "object") &&
      ("alg" in sig) && (typeof(sig.alg) == "string") &&
      ("nonce" in sig) && this.isB64String(sig.nonce) &&
      ("sig" in sig) && this.isB64String(sig.sig) &&
      ("jwk" in sig) && this.validJWK(sig.jwk));
  },

  validJWK: function(jwk) {
    return ((typeof(jwk) == "object") && ("kty" in jwk) && (
      ((jwk.kty == "RSA")
        && ("n" in jwk) && this.isB64String(jwk.n)
        && ("e" in jwk) && this.isB64String(jwk.e)) ||
      ((jwk.kty == "EC")
        && ("crv" in jwk)
        && ("x" in jwk) && this.isB64String(jwk.x)
        && ("y" in jwk) && this.isB64String(jwk.y))
    ) && !("d" in jwk));
  },

  // A simple, non-standard fingerprint for a JWK,
  // just so that we don't have to store objects
  keyFingerprint: function(jwk) {
    switch (jwk.kty) {
      case "RSA": return jwk.n;
      case "EC": return jwk.crv + jwk.x + jwk.y;
    }
    throw "Unrecognized key type";
  }
};
