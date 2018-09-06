var exports = module.exports = {};

const JWT = require('jsonwebtoken');
const _ = require('lodash');
const jwkToPem = require('jwk-to-pem');
const jwksClient = require('jwks-rsa');

opts = {};
opts.private = true;

rcsOpts = {
    "rcsKeyPair" : {
        "p": "6pqVTY8RcfuZYonkv2qRMvP1TMqr1niWJFHqeOrCpqhxscpC6G1r7wy7IsvJxqQHoravtPfkwRScCps8xq6bRAc-m8yTrQrlsq-VePxXpXpgqpeN0ioVC7H7KnCfIrQ1vXREFUYIH8OIaBM66gEmyb3QtH8BeiYcuF8lUZvqPcE",
        "kty": "RSA",
        "q": "yYQBkoBKWvXM6GGRUEAxAA9a8Zf7cb5hhJyluK0S9d8JDWqeaznfe40442GecJ_q7t5t4BiaEGnhwJM0o7Gau0wVFI8VEw4JiXjOc7DS5MfF8rdYuO7papUAPykW9aNtwG-1wdYIf4qhAUeBNznzJy-Y9Wp2g6j6nuEkQ9yo5fM",
        "d": "YHad_vy2ZltA6a3bWwq273OimXZviRhpR4Rr-VJhetqx_c51hfQFfqWOdKdz8rYuQ3NA4f9CXLvlrqsgmNnb04yQfI0X947rGS2qRQDmwkFLRCUUA_rXut9pJ-jYcjjCWwE9lVgHDjekmaPDU76j3PfAhTfFvt5EVxsQ4eeN3Q7eQu8bnSSmmFsTY5TIF4-dZYCS-XEbESuhHs6B6wjql2GQwbWlNTFFAZAhXxUjZaOlvENBlLcQjCn6mlr2WTCW6THw5l5W-4tUDEW2l9b2CJ-fRmQDxxRAFIZU5aa02mvM0cAPfae4EXVwQfVeHAEj0weM0DfcuE9x2s0OgYZDgQ",
        "e": "AQAB",
        "use": "sig",
        "kid": "f24865b5-103f-4a18-ad37-2104c6268c28",
        "qi": "w6gmzQvE1QXHjhRRNmezlFlxUubg8NruyXEZLoPY9kKNYTa7agd7uZ669U_eC35BxQE9oHd-gK8WIFWIzB9ixVbJgG8BCNlkM2VkfwAaLSe1UTOEXgEjw_Mi9ou30lVYcjxVfqLJJjPTg4FAUHkC7JIpgGf-RY4MjvzydmXKz4o",
        "dp": "tOEklhzlhW1H8KqCnHbspk1j5qYoYP6uPCiQUFQoadhbeImKlquu2SuGqShYVPgpDvItfKjYTWm3eZIBBOqguY2gXv0XKwbI3MD1zMc6SFKXb0_UP6LEgTTjgvA8McSh3oVi7MgHAX5_kEarWLo0jrzzygZWPDhgUmLBYi-FJcE",
        "alg": "RS256",
        "dq": "L11jsTeOQor7urMUILS1z7nMOnTqmPWSnkTjfuDPUBM4YXrp-XIE4Vl0QZ20S-yKn9KQKNgffjQk58qx2LfqEpPzcH2hCnWGMFXA0NiC-VsrX71QkUc2feK_yBi0WNAs_8pCAml4XeILre1MpdptGIzLewOnD5MsNSPeDkVTPZk",
        "n": "uKxYX72iWfmEuNI0OCGyScTVSROuuUsmn8qK0p4f0kPNqSbnZHc6TBsMngNPUnZySyMRTmywuVNoNmMj17ncIVsEWmhp_ER9bKvBHRdh58GVasDc8VtQTk4OqsV4l-fOEvJXf7d2_KXEYPMbflflOalHhVw8Q4r5y8DLYid3z_FGxbTndxrrBStc4TelX_1dvnoK74rr1N_DCLBuFokk-HX0VWA1SnqsI4XF53XMwJQ2Rf8bi0bWuRoIgT7YkVWjYyg2KOBzS7iWyFyHETh-TiDXMHWI2tnEkmzFCSueQyNuFA1aRFvdkeFdYoY6SwB0SkOyJrR5cHLh3Fk86z5DMw"
    },
    "AMOAuth2KeyURI" : "http://id.init8.net:8080/openam/oauth2/connect/jwk_uri"
}

const myJSONKeySet = {
    "keys": [rcsOpts.rcsKeyPair]
}

const myPEMKeyPriv = jwkToPem(rcsOpts.rcsKeyPair, opts);
const myPEMKeyPub = jwkToPem(rcsOpts.rcsKeyPair, {
    "private": false
});

exports.sign = function (claims) {
    const myPEMKeyPriv = jwkToPem(rcsOpts.rcsKeyPair, opts);
    claims.aud = claims.iss;
    claims.iss = "rcs";
    claims.decision = true;

    return new Promise(function (resolve, reject) {
        JWT.sign(claims, myPEMKeyPriv, {
            "algorithm": rcsOpts.rcsKeyPair.alg,
            "keyid": rcsOpts.rcsKeyPair.kid
        }, function (err, token) {
            if (err) {
                console.log("[RCS] Oooops. Err during signing." + err)
                reject(err)
            } else {
                console.log("[RCS] Signed JWT: " + token);
                try {
                    var dec = JWT.verify(token, myPEMKeyPub, {
                        "algorithms": ["RS256", "RS384"]
                    });
                } catch (err) {
                    console.log("[RCS] Error while verifying signature:" + err)
                }
                resolve(token)
            }
        });
    })
}

function verify(token, decoded) {
    var options = {};
    var client = jwksClient({
        jwksUri: rcsOpts.AMOAuth2KeyURI
    });

    function getKey(header, callback) {
        client.getSigningKey(header.kid, function (err, key) {
            var signingKey = key.publicKey || key.rsaPublicKey;
            callback(null, signingKey);
        });
    }

    return new Promise(function (resolve, reject) {
        JWT.verify(token, getKey, options, function (err, decoded) {
            if (err) {
                reject(err)
            } else {
                console.log("[RCS] Decoded: " + JSON.stringify(decoded));
                resolve(decoded)
            }
        });
    })
}
exports.decode = function (encjwt) {
    var verifyPromise = verify(encjwt);

    return verifyPromise.then(result => {
        return result;
    }, err => {
        return result;
    })
}

exports.getJWK = function () {
    return myJSONKeySet
}
