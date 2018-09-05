const njwk = require('node-jwk');
const njwt = require('njwt');
const _ = require('lodash');
const bpPromise = require('bluebird');
const jwkToPem = require('jwk-to-pem')

// myJSONKey = {
//     "alg": "RS256",
//     "kty": "RSA",
//     "use": "sig",
//     "x5c": [
//       "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMnjZc5bm/eGIHq09N9HKHahM7Y31P0ul+A2wwP4lSpIwFrWHzxw88/7Dwk9QMc+orGXX95R6av4GF+Es/nG3uK45ooMVMa/hYCh0Mtx3gnSuoTavQEkLzCvSwTqVwzZ+5noukWVqJuMKNwjL77GNcPLY7Xy2/skMCT5bR8UoWaufooQvYq6SyPcRAU4BtdquZRiBT4U5f+4pwNTxSvey7ki50yc1tG49Per/0zA4O6Tlpv8x7Red6m1bCNHt7+Z5nSl3RX/QYyAEUX1a28VcYmR41Osy+o2OUCXYdUAphDaHo4/8rbKTJhlu8jEcc1KoMXAKjgaVZtG/v5ltx6AXY0CAwEAAaMvMC0wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUQxFG602h1cG+pnyvJoy9pGJJoCswDQYJKoZIhvcNAQEFBQADggEBAGvtCbzGNBUJPLICth3mLsX0Z4z8T8iu4tyoiuAshP/Ry/ZBnFnXmhD8vwgMZ2lTgUWwlrvlgN+fAtYKnwFO2G3BOCFw96Nm8So9sjTda9CCZ3dhoH57F/hVMBB0K6xhklAc0b5ZxUpCIN92v/w+xZoz1XQBHe8ZbRHaP1HpRM4M7DJk2G5cgUCyu3UBvYS41sHvzrxQ3z7vIePRA4WF4bEkfX12gvny0RsPkrbVMXX1Rj9t6V7QXrbPYBAO+43JvDGYawxYVvLhz+BJ45x50GFQmHszfY3BR9TPK8xmMmQwtIvLu1PMttNCs7niCYkSiUv2sc2mlq1i3IashGkkgmo="
//     ],
//     "n": "yeNlzlub94YgerT030codqEztjfU_S6X4DbDA_iVKkjAWtYfPHDzz_sPCT1Axz6isZdf3lHpq_gYX4Sz-cbe4rjmigxUxr-FgKHQy3HeCdK6hNq9ASQvMK9LBOpXDNn7mei6RZWom4wo3CMvvsY1w8tjtfLb-yQwJPltHxShZq5-ihC9irpLI9xEBTgG12q5lGIFPhTl_7inA1PFK97LuSLnTJzW0bj096v_TMDg7pOWm_zHtF53qbVsI0e3v5nmdKXdFf9BjIARRfVrbxVxiZHjU6zL6jY5QJdh1QCmENoejj_ytspMmGW7yMRxzUqgxcAqOBpVm0b-_mW3HoBdjQ",
//     "e": "AQAB",
//     "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
//     "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"
//   }

myJSONPubKey = {
    "kty": "RSA",
    // "d": "ewOIz8P30C7Itww2MMrt2W1R_N2I3pme762z1zYH0JczBxJTJLPGoF4clNrxP4Yf6OsqHydyVxN4eT-0gqUzzvmH6OeQ-GDDlD6uTNe2eK6RP0dK6pgkyzw9YZGh9rijJY3iCbf5zl06-9TO2pF75RO2T_LiYTCXociftDGaJF6TNXQSBTIvjCCJhatOM2hliJil2SAPLAKfvRjAqNHLhlFgoMnL6nZuf-XbQjImeJME22PtR8YF88rFxqXJd-9kwVwMMi6mRTpV-XABEhYHqpWRhFhE4MChr9Oo0eChdHAsOmelvhCmVrQzu4RWWrqSbZJ3vp1qt3yqTt2JUW_FAQ",
    "e": "AQAB",
    "use": "sig",
    "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
    "alg": "RS256",
    "n": "go9i798yUYJcUX53B9HLG_GJdq4oBjZkJLfOka72OxthrCLASYaVNWFkr2Yy7dwFL8S1-k9mCOvHa78RNfLEuD7hDaRHBqDIabYKeGlASnJTIZqk1lF2dtCpVtacQdzoxZPIwm43_Ivzpl3Y9_zPRKx_IDr60FstnjOFpu2sOKP_VM8f3AKQwqZ43Vn3CamVDcsJB90z5TEvBdquwnLKXiR3dQOLvUo2_8fkMk3Fd1FtpcDLMF8yzkSBAoNNMaZsDxBjPvU-Gr9DczdaPT3Pbvy2hqIs5k_O844w8RAaZobfTZwvuGrrxZoqc1zTmYbmIEtEPMZsWRp_W2axq-PBtw"
  },

  myJSONKeyPair = {
    "kty": "RSA",
    //"d": "ewOIz8P30C7Itww2MMrt2W1R_N2I3pme762z1zYH0JczBxJTJLPGoF4clNrxP4Yf6OsqHydyVxN4eT-0gqUzzvmH6OeQ-GDDlD6uTNe2eK6RP0dK6pgkyzw9YZGh9rijJY3iCbf5zl06-9TO2pF75RO2T_LiYTCXociftDGaJF6TNXQSBTIvjCCJhatOM2hliJil2SAPLAKfvRjAqNHLhlFgoMnL6nZuf-XbQjImeJME22PtR8YF88rFxqXJd-9kwVwMMi6mRTpV-XABEhYHqpWRhFhE4MChr9Oo0eChdHAsOmelvhCmVrQzu4RWWrqSbZJ3vp1qt3yqTt2JUW_FAQ",
    "e": "AQAB",
    "use": "sig",
    "kid": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
    "alg": "RS256",
    "n": "go9i798yUYJcUX53B9HLG_GJdq4oBjZkJLfOka72OxthrCLASYaVNWFkr2Yy7dwFL8S1-k9mCOvHa78RNfLEuD7hDaRHBqDIabYKeGlASnJTIZqk1lF2dtCpVtacQdzoxZPIwm43_Ivzpl3Y9_zPRKx_IDr60FstnjOFpu2sOKP_VM8f3AKQwqZ43Vn3CamVDcsJB90z5TEvBdquwnLKXiR3dQOLvUo2_8fkMk3Fd1FtpcDLMF8yzkSBAoNNMaZsDxBjPvU-Gr9DczdaPT3Pbvy2hqIs5k_O844w8RAaZobfTZwvuGrrxZoqc1zTmYbmIEtEPMZsWRp_W2axq-PBtw"
  }

const ks = { "keys": [myJSONPubKey] };
const kspair = { "keys": [myJSONKeyPair] };
const myKeyId = myJSONKeyPair.kid;
const myPEMKey = jwkToPem(myJSONPubKey);
console.log(JSON.stringify(myPEMKey));
const myKey = njwk.JWK.fromJSON(JSON.stringify(myJSONPubKey));
const myKeySet = njwk.JWKSet.fromObject(ks);

const time = Math.floor(_.now() / 1000);

const claims = {
    iss: 'itsME',
    aud: 'myAudience',
    iat: time,
    exp: time + 3600
};

console.log("Hello");

return bpPromise.try(() => {
    const keySet = njwk.JWKSet.fromObject(kspair);
    const jwk = keySet.findKeyById(myKeyId);

    if (!jwk) {
        return bpPromise.reject(new Error('Huh, my key is not there...'));
    }
    console.log("JWK: " + JSON.stringify(jwk));
    const keyPEM = jwk.key.toPrivateKeyPEM();
    console.log("PEM: " + jwk.key.toPrivateKeyPEM());
    const jwt = njwt.create(claims, myPEMKey, jwk.alg);

    return bpPromise.resolve(jwt.compact());
})
.catch(err => {
    return bpPromise.reject(err);
});