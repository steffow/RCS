var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var urlencodedParser = bodyParser.urlencoded({
    extended: true
});
var signing = require("./sign.js");
var html = require("./html.js");
var reqDecodedResult;

app.get('/rcs/jwk.pub', function (req, res) {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(signing.getJWK()));
});

app.get('/rcs/consent', function (req, res) {
    reqDecoded = signing.decode(req.query.consent_request);
    res.setHeader('content-type', 'text/html');
    res.write("<H1>CONSENT PAGE</H1>");
    reqDecoded.then(result => {
        reqDecodedResult = result;
        var scopeTokens = Object.keys(reqDecodedResult.scopes);
        html.displayConsent(scopeTokens, res);
    })
});

app.post('/rcs/consent', urlencodedParser, function (req, res) {
    var consentApprovalURL = reqDecodedResult.consentApprovalRedirectUri;
    var scopeTokens = Object.keys(req.body);
    var submit = scopeTokens.indexOf("submit");
    if (submit > -1) {
        scopeTokens.splice(submit, 1);
    }
    reqDecodedResult.scopes = scopeTokens; // Overriding the scopes key in ConsentReq with user consent
    res.setHeader('content-type', 'text/html');
    res.write("<h2>Thank you</h2>")
    var signedJWT = signing.sign(reqDecodedResult);
    signedJWT.then(result => {
        res.end('<form action="' + consentApprovalURL + '" method="post"><input type="hidden" value=' + result + ' name="consent_response" />' +
            '<input type="submit" value="Submit Consent" name="submit"></input>' +
            '</form>')
    })
});

var server = app.listen(3000, function () {
    var host = server.address().address;
    var port = server.address().port;
    console.log("Remote Consnet Service listening at http://%s:%s", host, port);
});