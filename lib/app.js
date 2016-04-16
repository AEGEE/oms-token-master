//PREAMBLE STUFF
var assert = require('assert');
var ldap = require('./config/ldap.js');

var log = require('./config/logger');

var config = require('./config/config.json');
var jwt    = require('jsonwebtoken');

var LDAP_TOP_DN = 'o=aegee, c=eu';

var redis = require("redis");
var redisClient = redis.createClient(config.redis.port, config.redis.url);


var appInitialSetup = function appInitialSetup(){

  ldap.bindSuper();
  redisClient.on("error", function (err) {
    console.log("Error " + err);
  });

}();


//API DEFINITION

//v0.0.6 middleware
exports.validateToken = function(req, res, next) {

  // check header or url parameters (no post parameter) for token
  var token = req.headers['x-access-token'] || req.query.token ;
  doVerification(token, req, res, next);

};

//v0.0.6 endpoint
exports.verifyToken = function(req, res, next) {

  // check post parameters or url parameters for foreign (3rd party) token
  var foreignToken = req.params.token || req.query.token ;
  doVerification(foreignToken, req, res, function(req, res){
    if(req.decoded){//FIXME Anyway this is set to true with the previous token verification
      return res.send(200, { success: true, message: 'The dude is chill.' });
    }
  });

};


//v0.0.6 endpoint
exports.authenticate = function(req, res, next) {
//HERE IS THE LOOKUP IN LDAP + JWT generation (and saved in redis LUT)
  var uid = req.params.username;
  var password = req.params.password;
  
  log.info(uid, 'User is requesting a token');

  // find the user  
  ldap.bindUser('uid='+uid+',ou=services,o=aegee,c=eu', password, function(err) {
    if(err){
      log.info({err: err}, 'LDAP service binding');
      return res.json({ success: false, message: 'Authentication failed. ' });
    }
    
    var searchDN = 'ou=services, ' + LDAP_TOP_DN;
    var filter = '(uid='+uid+')';
    ldap.searchLDAP(filter, searchDN, res, generateJWToken)
  });

  //console.log("done2");
};

exports.debugShowAllTokens = function(req, res, next) {
  redisClient.keys("*", redis.print);
  res.send(200, "poi ci scrivo qualcosa");
}

//HELPER or INTERNAL METHODS
//old one: was verifying the signed JWT. now we also have non-JWT so we must just use redis to look up
var doVerification2 = function doVerification(token, req, res, next) {

  if(token){
    jwt.verify(token, config.secret, function(err, decoded) {      
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' });    
      } else {
        req.decoded = decoded;    
        next();
      }
    });
  }else{
    // return error if no token
    return res.send(403, { success: false, message: 'No token provided.' });
  }

};
var doVerification = function doVerificationR(token, req, res, next) {

  if(token){
    redisClient.get(token, function(err, decoded) {      
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' });    
      } else {
        if(decoded===null) {
          return res.json({ success: false, message: 'Token not in keyring' });    
        } else {
          req.decoded = decoded;
          return next();
        }
      }
    });
  }else{
    // return error if no token
    return res.send(403, { success: false, message: 'No token provided.' });
  }

};

//v0.1.0
function generateJWToken(res, user){ 

  user = user[0]; //The query always returns an array

  var token = jwt.sign(user, config.secret); //TODO: add a nonce or sth

  //add token to the redis keychain
  redisClient.set("service:"+user.uid, token, console.log("generated JWT for " + user.uid));
  redisClient.set(token, "service:"+user.uid, console.log("generated JWT for " + user.uid + ", JWT as key"));

  //after all is well, before returning the token 
  // re-bind with privileged user
  ldap.bindSuper(function(err) { 
      log.info({err: err}, 'LDAP client binding SU after generating token');
      assert.ifError(err);

      // return the information including token as JSON
      res.json({
        success: true,
        message: 'Enjoy your token!',
        token: token    
      });
    });

};


//v0.1.0
exports.generateToken = function(req, res, next){ 

  //check params for nonce or other stuff
  var user = req.body.user;

  //var token = jwt.sign(user, config.secret);
  var token = randomString(64);

  //add token to the redis keychain
  tokens[token] = uid;
  redisClient.set("rememberme:"+uid, token, console.log("generated RMT for " + user));
  redisClient.set(token, "rememberme:"+uid, console.log("generated RMT for " + user + ", RMT as key"));

  // return the information including token as JSON
  //PERHAPS AFTER A CALLBACK OF REDIS
      res.json({
        success: true,
        message: 'Enjoy your token!',
        token: token    
      });
    

};


function expireToken (req,res,next){

  var token = req.body.token;


  var uid = tokens[token];
  // invalidate the single-use token
  delete tokens[token];
  
  redisClient.get(token, function(err, value){ 
      if (err) {
        console.log("catastrophic failure");
        return next(err);
      }

      uid = value;

      redisClient.del(token, function(err, result){
          if (err || result !== "OK") {
            console.log("catastrophic failure");
            return next(err);
          }

          return next(uid);
      });
  });


}

//INTERNAL STUFF


//from passport-remember-me example
function randomString(len) {
  var buf = []
    , chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    , charlen = chars.length;

  for (var i = 0; i < len; ++i) {
    buf.push(chars[getRandomInt(0, charlen - 1)]);
  }

  return buf.join('');
};

function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}


var tokens = {}; //TODO: take from Redis
