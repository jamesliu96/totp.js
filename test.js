var TOTP = require("./lib/totp");

console.log("now()=" + Math.floor(TOTP.util.now() / 1000));
var r = TOTP.totp("testkeyhellofoobar", TOTP.util.now(), 6, "sha1");
console.log("sha1(testkeyhellofoobar)   = " + r);
r = TOTP.totp("testkeyhellofoobar", TOTP.util.now(), 6, "sha256");
console.log("sha256(testkeyhellofoobar) = " + r);
r = TOTP.totp("testkeyhellofoobar", TOTP.util.now(), 6, "sha512");
console.log("sha512(testkeyhellofoobar) = " + r);
console.log("parseHex(2a)=" + TOTP.util.parseHex("2a"));
console.log("parseHexAt(9b7d2aaa9f,2)=" + TOTP.util.parseHexAt("9b7d2aaa9f", 2));
