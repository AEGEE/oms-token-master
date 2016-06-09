
var restify = require('restify');
var app = require('./app.js'); //the real place where the API callbacks are
var log = require('./config/logger.js');

var config = require('./config/config.json');

var server = restify.createServer({
    name: 'keyMaster',
    log: log
});

server.use(restify.queryParser());
server.use(restify.bodyParser());
server.use(restify.CORS());


//Define your API here

//this endpoint is for public access
server.post({path: '/authenticate', version: '0.0.6'} , app.authenticate );

//unsecured, deleteme
server.get({path: '/DEBUGshow', version: '0.1.0'} , app.debugShowAllTokens);

server.get({path: '/DEBUGdelete', version: '0.1.0'} , app.debugDelAllTokens);


//for endpoints declared from here onwards, apply the middleware "verifyToken"
server.use( app.validateToken );

//GET: a list of the tokens, so the user(admin) can decide if revoke them or not
//server.get({path: '/DEBUGshow', version: '0.1.0'} , app.debugShowAllTokens);

//POST: a token to be authenticated
server.post({path: '/verify' , version: '0.0.6'} , app.verifyToken );

//POST: credentials/nonces/other to generate a token
server.post({path: '/requesttoken' , version: '0.0.6'} , app.generateToken );

server.post({path: '/expiretoken' , version: '0.0.6'} , app.expireToken );

//POST: token to expire
//server.post({path: '/expiretoken' , version: '0.0.6'} , app.expireToken );


server.listen(config.port, function() {
    console.log('%s listening at %s ', server.name, server.url);
});
