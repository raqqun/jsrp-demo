const express = require('express');
const jsrp = require('jsrp');
const app = express();
const bodyParser = require('body-parser')

app.get('/', function(req, res){
    res.sendFile('index.html', { root: __dirname } );
});

app.get('/register.html', function(req, res){
    res.sendFile('register.html', { root: __dirname } );
});

app.get('/login.html', function(req, res){
    res.sendFile('login.html', { root: __dirname } );
});

// memdown is an in memory db that disappears when you restart the process
const memdown = require('memdown')
const db = new memdown('srp')
const cache = new memdown('challenge');

// create application/x-www-form-urlencoded parser
const urlencodedParser = bodyParser.urlencoded({ extended: false })

app.post('/save', urlencodedParser, function(req, res){
    if (!req.body) return res.sendStatus(400)

    const data = {salt: req.body.salt, verifier: req.body.verifier};

    db.put(req.body.username , JSON.stringify(data), function (err) {
        if (err) throw err
    })

    res.send('Welcome ' + req.body.username + '!</br>You can now attempt to authenticated at <a href="/login.html">the login page</a>.');

});

app.post('/challenge', urlencodedParser, function(req, res){
    if (!req.body) return res.sendStatus(400)
    const username = req.body.username

    if( typeof username === 'undefined') {
        return res.sendStatus(400);
    } else {
        db.get(username, { asBuffer: false }, function(err,value){
            if(err) {
                return res.sendStatus(204) // https://stackoverflow.com/a/11760249/329496
            } else {
                res.setHeader('Content-Type', 'application/json');

                const result = JSON.parse(value);
                const salt = result.salt;
                const verifier = result.verifier;
                const jsrpServer = new jsrp.server();

                jsrpServer.init({ salt: salt, verifier: verifier }, function () {
                    // Server instance is ready to be used here.
                    const B = jsrpServer.getPublicKey();
                    const salt = jsrpServer.getSalt();

                    cache.put(username, JSON.stringify({b: jsrpServer.getPrivateKey()}), function (err) {
                        if (err) throw err
                    })

                    const response = {salt: salt, B: B};

                    res.send(JSON.stringify(response));
                });
            }
        })
    }
});

app.post('/authenticate', urlencodedParser, function(req, res){
    if (!req.body) return res.sendStatus(400)
    const creds = req.body.credentials

    if( typeof creds === 'undefined'){
        return res.sendStatus(400);
    } else {
        const credentials = JSON.parse(creds)

        const username = credentials.username
        const A = credentials.A
        const M1 = credentials.M1

        db.get(username, { asBuffer: false }, function(err,value){
            if(err) {
                return res.sendStatus(204) // https://stackoverflow.com/a/11760249/329496
            } else {
                res.setHeader('Content-Type', 'application/json');

                const result = JSON.parse(value);
                const salt = result.salt;
                const verifier = result.verifier;

                const jsrpServer = new jsrp.server();

                cache.get(username, { asBuffer: false }, function(err, value){
                    const result = JSON.parse(value);

                    jsrpServer.init({ salt: salt, verifier: verifier, b: result.b }, function () {
                        // Server instance is ready to be used here.

                        jsrpServer.setClientPublicKey(A);
                        if (jsrpServer.checkClientProof(M1)) {
                            console.log('client proof checks');
                            const M2 = jsrpServer.getProof();
                            const M2Encoded = encodeURIComponent(M2);
                            console.log('shared key:', jsrpServer.getSharedKey());


                            const response = {M2: M2};
                            return res.send(JSON.stringify(response));
                        }
                        else {
                            console.log('no proof');
                            return res.sendStatus(403);
                        }
                    });
                })
            }
        })
    };
});

app.get('/home', function(req,res){
    const username = req.query.username;
    res.send('Welcome ' + username + ' you have successfully authenticated!');
});

const server = app.listen(8080, function(){
    console.log('Node has started on port 8080');
});

exports.closeServer = function(){
    server.close();
};
