
var assert = require('assert');

var config = require('./config.json');
var log = require('./logger');

var ldap = require('ldapjs');

var client = ldap.createClient({
  url: config.ldap.url,
  log: log
});

var LDAP_TOP_DN = 'o=aegee, c=eu';

exports.bindSuper = function(next){
    bindUser('cn=admin,' + LDAP_TOP_DN, config.ldap.rootpw, next);
};

this.bindSuper();

function bindUser(user, pass, next){

  if(next === undefined){
    next = function(err) {
      client.log.info({err: err}, 'LDAP client binding of '+user);
      assert.ifError(err);
    };
  }

  client.bind( user, pass, next);
};

exports.bindUser = bindUser;

//Usage: <filter, basedn, response, callback to execute on end>
//  searchLDAP("objectClass=aegeePersonFab", 'ou=people, '+ldap_top_dn, res, function(){...} );
//v0.1.2
exports.searchLDAP = function(searchFilter, searchDN, res, next) {

  //if next is not defined, just send the search result as response
  if(next === undefined){
    next = function(res, data){ 
                  res.send(200,data); 
               };
  }

  //set search parameters
    var opts = {
      filter: searchFilter,
      scope: 'sub',
      attributes: ''
    };

    var results = [];

    client.search(searchDN, opts, function(err, ldapres) {
        log.debug({searchDN: searchDN, searchFilter: searchFilter, err: err}, 'Client search');
        assert.ifError(err);

        ldapres.on('searchEntry', function(entry) {
          log.debug({entry: entry.object}, 'Client search: searchEntry');
          results.push(entry.object);
        });
        ldapres.on('searchReference', function(referral) {
          log.debug({referral: referral.uris.join()}, 'Client search: searchReference');
        });
        ldapres.on('error', function(err) {
          log.error({searchDN: searchDN, searchFilter: searchFilter, err: err}, 'Client search: error');
        });
        ldapres.on('end', function(result) {
          log.debug({result: result.status, results: results}, 'Client search: end');
          next(res, results);
        });
    });

};
