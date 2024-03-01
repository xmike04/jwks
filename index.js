const crypto = require('crypto');
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());

const keys = {};

function generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, // Standard for RSA keys
    });

    const kid = crypto.randomBytes(16).toString('hex'); // Generate a random Key ID
    const expiry = Date.now() + (24 * 60 * 60 * 1000); // Key expiry set to 24 hours from now

    keys[kid] = { publicKey, privateKey, kid, expiry };
    return { kid }; // Return the Key ID
}

generateKeyPair();

// JWKS endpoint
app.get('/jwks', (req, res) => {
    const jwks = {
        keys: Object.values(keys).filter(key => key.expiry > Date.now()).map(({ publicKey, kid }) => ({
            kty: 'RSA',
            kid,
            use: 'sig',
            alg: 'RS256',
            n: publicKey.export({ type: 'pkcs1', format: 'pem' }).match(/-----BEGIN PUBLIC KEY-----(.*)-----END PUBLIC KEY-----/s)[1].replace(/(\r\n|\n|\r| )/gm, ""),
            e: 'AQAB',
        }))
    };
    res.json(jwks);
});

// Authentication endpoint
app.post('/auth', (req, res) => {
    const { expired } = req.query;
    let selectedKey;

    if (expired === 'true') {
        selectedKey = Object.values(keys).find(key => key.expiry <= Date.now());
    } else {
        selectedKey = Object.values(keys).find(key => key.expiry > Date.now());
    }

    if (!selectedKey) {
        const { kid } = generateKeyPair();
        selectedKey = keys[kid];
    }

    const token = jwt.sign({ sub: 'user123' }, selectedKey.privateKey, {
        algorithm: 'RS256',
        expiresIn: '1h',
        keyid: selectedKey.kid,
    });

    res.json({ token });
});

if (process.env.NODE_ENV !== 'test') {
    const PORT = 8080;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
