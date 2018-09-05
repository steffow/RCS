var exports = module.exports = {};

const JWT = require('jsonwebtoken');
const _ = require('lodash');
const jwkToPem = require('jwk-to-pem');
var jwksClient = require('jwks-rsa');

opts = {};
opts.private = true;

const myJSONKeyPair = {
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
  }
  

const AMOAuth2KeyURI = "http://id.init8.net:8080/openam/oauth2/connect/jwk_uri"

const AMOAuth2KeySet = {
    "keys": [{
        "kty": "RSA",
        "kid": "DkKMPE7hFVEn77WWhVuzaoFp4O8=",
        "use": "enc",
        "alg": "RSA-OAEP",
        "n": "i7t6m4d_02dZ8dOe-DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn_ScFHpq8Tx4BzhcDb6P0-PHCo-bkQedxwhbMD412KSM2UAVQaZ-TW-ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s_BS1obWUOC-0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ_0ts3NsL83413NdbWYh-ChtP696mZbJozflF8jR9pewTbQ",
        "e": "AQAB"
    }, {
        "kty": "RSA",
        "kid": "4iCKFB0RXIxytor1r3ToBdRievs=",
        "use": "sig",
        "alg": "RS256",
        "n": "i7t6m4d_02dZ8dOe-DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn_ScFHpq8Tx4BzhcDb6P0-PHCo-bkQedxwhbMD412KSM2UAVQaZ-TW-ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s_BS1obWUOC-0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ_0ts3NsL83413NdbWYh-ChtP696mZbJozflF8jR9pewTbQ",
        "e": "AQAB"
    }, {
        "kty": "RSA",
        "kid": "DkKMPE7hFVEn77WWhVuzaoFp4O8=",
        "use": "enc",
        "alg": "RSA-OAEP-256",
        "n": "i7t6m4d_02dZ8dOe-DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn_ScFHpq8Tx4BzhcDb6P0-PHCo-bkQedxwhbMD412KSM2UAVQaZ-TW-ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s_BS1obWUOC-0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ_0ts3NsL83413NdbWYh-ChtP696mZbJozflF8jR9pewTbQ",
        "e": "AQAB"
    }, {
        "kty": "RSA",
        "kid": "DkKMPE7hFVEn77WWhVuzaoFp4O8=",
        "use": "enc",
        "alg": "RSA1_5",
        "n": "i7t6m4d_02dZ8dOe-DFcuUYiOWueHlNkFwdUfOs06eUETOV6Y9WCXu3D71dbF0Fhou69ez5c3HAZrSVS2qC1Htw9NkVlLDeED7qwQQMmSr7RFYNQ6BYekAtn_ScFHpq8Tx4BzhcDb6P0-PHCo-bkQedxwhbMD412KSM2UAVQaZ-TW-ngdaaVEs1Cgl4b8xxZ9ZuApXZfpddNdgvjBeeYQbZnaqU3b0P5YE0s0YvIQqYmTjxh4RyLfkt6s_BS1obWUOC-0ChRWlpWE7QTEVEWJP5yt8hgZ5MecTmBi3yZ_0ts3NsL83413NdbWYh-ChtP696mZbJozflF8jR9pewTbQ",
        "e": "AQAB"
    }, {
        "kty": "EC",
        "kid": "pZSfpEq8tQPeiIe3fnnaWnnr/Zc=",
        "use": "sig",
        "alg": "ES512",
        "x": "AHdVKbNDHym-MiUh6caaod_ktp8PXN6g1zIKLzlaCSOZP82KKaQsfwltAKnMrw129nVx-2kt8x1J1pp1ADe9HtXt",
        "y": "AUqhRKcYvA6lElI3UrfqvpuhVsyEFBQ4cM_E9v4WGnRc_priiTVa_UC7YfCtQJT9F8Oc21v_i57Sp3Mq_vw5ueRd",
        "crv": "P-521"
    }, {
        "kty": "EC",
        "kid": "I4x/IijvdDsUZMghwNq2gC/7pYQ=",
        "use": "sig",
        "alg": "ES384",
        "x": "k5wSvW_6JhOuCj-9PdDWdEA4oH90RSmC2GTliiUHAhXj6rmTdE2S-_zGmMFxufuV",
        "y": "XfbR-tRoVcZMCoUrkKtuZUIyfCgAy8b0FWnPZqevwpdoTzGQBOXSNi6uItN_o4tH",
        "crv": "P-384"
    }, {
        "kty": "EC",
        "kid": "Fol7IpdKeLZmzKtCEgi1LDhSIzM=",
        "use": "sig",
        "alg": "ES256",
        "x": "N7MtObVf92FJTwYvY2ZvTVT3rgZp7a7XDtzT_9Rw7IA",
        "y": "uxNmyoocPopYh4k1FCc41yuJZVohxlhMo3KTIJVTP3c",
        "crv": "P-256"
    }]
}

function init() {
    const time = Math.floor(_.now() / 1000);

    console.log("OPTS: " + JSON.stringify(opts));

    const myPEMKeyPriv = jwkToPem(myJSONKeyPair, opts);
    const myPEMKeyPub = jwkToPem(myJSONKeyPair, {"private": false});

    console.log("PEM: " + JSON.stringify(myPEMKeyPub));

    const claims = {
        "clientId": "test",
        "iss": "http://id.init8.net:8080/openam/oauth2",
        "csrf": "ZN666AMOUqLGFaxXrHojtNTXhDhlnHhYuE+dhzuDYVI=",
        "client_description": "",
        "aud": "rcs",
        "save_consent_enabled": false,
        "claims": {},
        "scopes": {
            "uid": null
        },
        "exp": 2536178948,
        "iat": 1536178768,
        "client_name": "test",
        "consentApprovalRedirectUri": "http://id.init8.net:8080/openam/oauth2/authorize?client_id=test&response_type=code&redirect_uri=http://localhost:3001/redirect&scope=uid&state=1234zy",
        "username": "demo"
    };

    JWT.sign(claims, myPEMKeyPriv, {
        algorithm: myJSONKeyPair.alg
    }, function (err, token) {
        console.log("Signed in init(): " + token + "\n\n");
        try {
            var dec = JWT.verify(token, myPEMKeyPub, {"algorithms": ["RS256", "RS384"]});
            console.log("\n\n Verified: " + JSON.stringify(dec))
        } catch (err) {
            console.log("Error while verifying signature: " + err)
        }
        
    });

    // console.log("Signed: " + JWT.sign({
    //     exp: Math.floor(Date.now() / 1000) + (60 * 60),
    //     data: claims
    // }, myPEMKeyPub));

}

exports.sign = function (claims) {
    const myPEMKeyPriv = jwkToPem(myJSONKeyPair, opts);
    console.log("Signing....");
    return new Promise(function(resolve,reject){
        JWT.sign(claims, myPEMKeyPriv, {
            algorithm: myJSONKeyPair.alg
        }, function (err, token) {
            if (err) {
                console.log("Oooops. Err during signing." + err)
                reject(err)
            } else {
                console.log("Signed JWT: " + token);
                resolve(token)
            }
        });
    })
}

function verify(token, decoded)  {
    var options = {};
    var client = jwksClient({
      jwksUri: AMOAuth2KeyURI
    });
    function getKey(header, callback){
      client.getSigningKey(header.kid, function(err, key) {
        var signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
      });
    }

    return new Promise(function(resolve, reject){
        JWT.verify(token, getKey, options, function(err, decoded) {
            if (err) {
                reject(err)
            } else {
                console.log("Decoded: " + JSON.stringify(decoded));
                resolve(decoded)
            }
          });
    })
}
exports.decode = function (encjwt) {
    var verifyPromise = verify(encjwt);
    var decoded;
    return verifyPromise.then(function(result){
        console.log("Promise Result: " + JSON.stringify(result));
        decoded = result;
        return decoded;
    }, function(err) {
        console.log(err);
        decoded = "Error during decoding";
        return decoded;
    })
}

exports.getJWK = function () {

    return myJSONKeyPair

}

init();
