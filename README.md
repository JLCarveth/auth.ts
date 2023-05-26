# auth.js

`auth.js` is a Node.js module that provides several functions for handling authentication and security in a Node.js application. It uses the `jsonwebtoken` library to generate and verify JSON Web Tokens (JWTs) and the Node.js `crypto` library to generate salts and hash passwords.

## Installation

Simply install the package from npm:
```
npm i @jlcarveth/auth.js
```

## Usage

To use the functions provided by `auth.js`, you need to import them into your code. Here's an example of how you might use the `generateToken` function to create a new JWT:

```javascript
import { generateToken } from "@jlcarveth/auth.js";

async function createToken() {
  const token = await generateToken({ email: 'user@example.com', role: 'admin' });
  console.log(token);
}
```

In this example, we import the `generateToken` function from the `auth.js` module and use it to create a new token for a user with the email address `user@example.com` and the role `admin`.

## Configuration

The `auth.js` module uses a secret key to sign JWTs. This key should be set as an environment variable named `SECRET_KEY`. Make sure to use a strong and unique secret key to prevent attackers from forging tokens.

## API

The `auth.js` module exports the following functions:

### generateToken(payload)

Generates a new JWT with the given payload. The payload should be an object, usually containing relevant information about the user requesting the token, such as an email address or role information.

### verifyToken(token)

Verifies the given JWT and returns its payload if it is valid. Throws an error if the token is invalid or expired.

### generateSalt()

Generates a new salt string for hashing passwords.

### hashPassword(password)

Hashes the given password using a randomly generated salt and returns the resulting hash.

### hashWithSalt(password, salt)

Hashes the given password using the specified salt and returns the resulting hash.

### comparePassword(password, hash)

Compares the given plaintext password with the given hash and returns `true` if they match, or `false` otherwise.

### middleware(request, response, next)

Express middleware function that verifies the JWT provided in the request's `x-access-token` header or `token` cookie. If the token is valid, it sets the `email` and `role` properties of the `response.locals` object and calls the `next` function. If the token is invalid or not provided, it sends an error response.

## License

[MIT](LICENSE)
