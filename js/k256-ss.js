const { SecretKey } = require("../pkg/vsss_rs");
const {Shamir} = require("../pkg");

// create a new random secret key
let sk = SecretKey.random();
console.log("sk = ", sk.toBytes());

// create secret sharing for the secret key
let shamir = new Shamir(2,3);
let shares = shamir.splitSecret(sk);
console.log("shares = ", shares);

// combine shares to reconstruct secret key
let shamir2 = new Shamir(2,3);
let sk2 = shamir2.combineShares([shares[0], shares[2]]);
console.log("sk combined = ", sk2.toBytes());

// load secret key from bytes
let sk3 = SecretKey.fromBytes(sk.toBytes());
console.log("sk from bytes = ", sk3.toBytes())