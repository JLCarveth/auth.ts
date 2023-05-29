/**
 * @module auth.js
 * @requires jsonwebtoken
 * @requires crypto Nodejs crypto library
 */

let crypto;
import jsonwebtoken from "jsonwebtoken";
import { merge } from "deeper-merge";

try {
  crypto = await import("node:crypto");
} catch (error) {
  console.error("auth.js requires the node:crypto module to run.");
  exit(1);
}

let secretKey = process.env.SECRET_KEY;
if (!secretKey) {
  throw new Error("SECRET_KEY environment variable not provided.");
}

/**
 * Generates a login-token
 * @param {String} email Unique email address to identify user
 * @param {*} role Optional role specification for RBAC
 * @returns
 */
function generateToken(payload) {
  return new Promise((resolve, reject) => {
    if (secretKey === "GENERATE A SECRET KEY") {
      throw new Error(
        "You have not generated a secret key. Set the `secretKey` env var."
      );
    }
    jsonwebtoken.sign(payload, secretKey, { expiresIn: "1h" }, (err, token) => {
      if (err) reject(err);
      else resolve(token);
    });
  });
}

/**
 * Ensures the token signature is valid, as well as expiry if applicable
 * @param {String} token token to be verified
 * @throws Error if signature or expiry invalid
 * @returns
 */
function verifyToken(token) {
  try {
    return jsonwebtoken.verify(token, secretKey);
  } catch (e) {
    throw e;
  }
}

/**
 * Generates a salt string for hashing passwords
 * @returns a 32-character randomly generated string
 */
function generateSalt() {
  return crypto.randomBytes(16).toString("hex");
}

/**
 * Returns a hashed string and the salt used to hash it, in the following format:
 *  hash:salt
 * *hash* is a 128 character string, *salt* is 32 characters, total string length
 * should be 161 characters
 * @param {String} password the password to be hashed
 * @returns hashed password + salt
 */
function hashPassword(password) {
  const salt = generateSalt();
  return hashWithSalt(password, salt);
}

/**
 * Hashes a password with a pre-defined salt value
 * @param {String} password to be hashed
 * @param {String} salt used for hashing
 * @returns hashed password + salt
 */
function hashWithSalt(password, salt) {
  const hash = crypto.createHmac("sha512", salt).update(password).digest("hex");

  return `${hash}:${salt}`;
}

/**
 * Compares a plaintext password with a hash.
 * @param {String} password
 * @param {String} hash
 * @returns true if password matches hash
 */
function comparePassword(password, hash) {
  let salt = hash.split(":")[1];
  return hashWithSalt(password, salt) === hash;
}

function middleware(request, response, next) {
  // cookie-parser is required to populate req.cookies
  const token = request.headers["x-access-token"] || request.cookies.token;

  if (token) {
    try {
      const payload = verifyToken(token);
      const locals = merge(res.locals, payload);
      res.locals = locals;
      next();
    } catch (err) {
      // Invalid token - Client Error
      response
        .status(401)
        .send({ success: false, error: "Token could not be verified" });
    }
  } else {
    response.status(400).send({
      success: false,
      error:
        "No token provided. Get a token and provide it with the x-access-token header.",
    });
  }
}

export {
  generateToken,
  verifyToken,
  generateSalt,
  hashPassword,
  hashWithSalt,
  comparePassword,
  middleware,
};
