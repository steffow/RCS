

var express = require('express');
var app = express();


var signing = require("./sign.js");

app.get('/rcs/jwk.pub', function (req, res) {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(signing.getJWK()));
});

app.get('/rcs/consent', function (req, res) {
    var consentApprovalURL; // this where the signed will be send back to
    reqDecoded = signing.decode(req.query.consent_request);
    res.setHeader('content-type', 'text/html');
    reqDecoded.then(result => {
        console.log("===> " + JSON.stringify(result));
        consentApprovalURL = result.consentApprovalRedirectUri;
        console.log("Approval URL: " + consentApprovalURL );
        var signedJWT = signing.sign(result);
        
        signedJWT.then(result => {
            console.log("Signed: " + result );
            res.end("<H1>CONSENT PAGE</H1>" +
        JSON.stringify(result, null, 4) + '<p>' + 
           '<form action="'+consentApprovalURL+'" method="post"><input type="hidden" value='+result+' name="consent_response" />' +
           '<input type="submit" value="Consent" name="submit"></input>' +
           '</form>')
        })
        
    })
});


var server = app.listen(3000, function () {

    var host = server.address().address;
    var port = server.address().port;

    console.log("Example app listening at http://%s:%s", host, port);

});