/**
 * @module cognito-helper
 */
require('dotenv').load();
const logger = require('log4js').getLogger('CognitoHelper');
const AWS = require('aws-sdk');
const configDefault = require('../configs/Cognito');

var normalizeProvider = function(providerName, token, config) {
  var isDeveloper = false;
  var cognitoProviderName = providerName;
  var prefixedToken = token;
  if(providerName === 'google') {
    cognitoProviderName = 'accounts.google.com';
  }
  else if(providerName === 'facebook') {
    cognitoProviderName = 'graph.facebook.com';
  }
  else if(providerName === 'amazon') {
    cognitoProviderName = 'www.amazon.com';
  }
  else if(providerName === 'twitter') {
    cognitoProviderName = 'api.twitter.com';
  }
  else {
    cognitoProviderName = config.COGNITO_DEVELOPER_PROVIDER_NAME;
    isDeveloper = true;
    if(providerName && token) {
      prefixedToken = providerName + config.COGNITO_SEPARATOR + token;
    }
  }
  return {
    name: cognitoProviderName,
    isDeveloper: isDeveloper,
    token: prefixedToken
  };
};


class Cognito {
  constructor(config) {
    if(!config) {
      config = configDefault;
      logger.info('cognito-helper loaded default config', config);
    }
    else {
      logger.info('cognito-helper loaded config', config);
    }
    this.config = config;

    this.cognitoIdentity = new AWS.CognitoIdentity();

    this.cognitoSync = new AWS.CognitoSync();
  }

  login(email, password, reset, callback) {
    this.getId(null, email, function(err, dataId) {
      if(err || !dataId) {
        callback({code: 404, error: 'does not exist ' + email});
      }
      else {
        checkPasswordCognitoSync(dataId.IdentityId, password, reset,
          function(err, data) {
            if(err) {
              callback({code: 401, error: err});
            }
            else {
              onLogin(null, email, null, null, null, dataId.IdentityId, callback);
            }
          });
      }
    });
  };

  signUp() {

  }

  me() {

  }

  unlink() {

  }

  /**
   * Retrieves CognitoIdenity ID given either a federated provider token
   * or user email.
   * @param {String} provider - name of a federated login provider like google,
   * amazon, facebook, twitter, stripe, paypal; or null for email as token
   * @param {String} token - access token gotten from provider thru oauth
   * or user's email
   * @param callback - function(err, data)
   */
  getId = function(provider, token, callback) {
    let params;
    const p = normalizeProvider(provider, token, this.config);

    if(p.isDeveloper) {
      params = {
        IdentityPoolId: this.config.COGNITO_IDENTITY_POOL_ID,
        DeveloperUserIdentifier: p.token,
        MaxResults: 10
      };
      logger.debug('lookupDeveloperIdentity', params);

      this.cognitoIdentity.lookupDeveloperIdentity(params, callback);
    }
    else {
      const logins = {};
      logins[p.name] = p.token;

      params = {
        IdentityPoolId: this.config.COGNITO_IDENTITY_POOL_ID,
        AccountId: this.config.AWS_ACCOUNT_ID,
        Logins:logins
      };
      logger.debug('getId', params);

      this.cognitoIdentity.getId(params, callback);
    }
  };
}

module.exports = Cognito;