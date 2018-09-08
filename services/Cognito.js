/**
 * @module cognito-helper
 */
require('dotenv').load();
const sha256 = require('js-sha256').sha256;
const logger = require('log4js').getLogger('CognitoHelper');
const AWS = require('aws-sdk');
const configDefault = require('../configs/Cognito');
const _ = require('lodash');

function encryptPassword(password) {
  return sha256(password);
}

function getRefreshTokenKey(provider) {
  return 'refresh' + provider;
}

function getProfileKey(provider) {
  return 'profile' + provider;
}

class Cognito {
  constructor(config) {
    if (!config) {
      config = configDefault;
      logger.info('cognito-helper loaded default config', config);
    } else {
      logger.info('cognito-helper loaded config', config);
    }
    this.config = config;

    this.cognitoIdentity = new AWS.CognitoIdentity();

    this.cognitoSync = new AWS.CognitoSync();
  }

  /**
   * Creates a user in CognitoIdentity with an email as a developer identifier.
   * Stores user name and password in CognitoSync.
   * @param {String} name - user's name
   * @param {String} email - email uniquely identifies a user
   * @param {String} password
   * @param callback - function(err, data)
   */
  async signUp(name, email, password) {
    let dataId;
    try {
      dataId = await this.getId(null, email);
    } catch (e) {
      console.log('error', e);
    }
    console.log('data', dataId);

    if (dataId) {
      return {
        statusCode: 409,
        body: JSON.stringify({
          error: 'An account already exists with ' + email,
        }),
      };
    }

    const dataDeveloperIdentity = await this.createDeveloperIdentity(email);

    console.log('dataDeveloperIdentity', dataDeveloperIdentity);

    await this.putPasswordCognito(dataDeveloperIdentity.IdentityId, password);

    const { id } = await this.onLogin(
      null,
      email,
      null,
      null,
      name,
      dataDeveloperIdentity.IdentityId,
    );

    return {
      statusCode: 200,
      body: JSON.stringify({
        id,
      }),
    };
  }

  login() {}

  me() {}

  unlink() {}

  /**
   * Retrieves CognitoIdenity ID given either a federated provider token
   * or user email.
   * @param {String} provider - name of a federated login provider like google,
   * amazon, facebook, twitter, stripe, paypal; or null for email as token
   * @param {String} token - access token gotten from provider thru oauth
   * or user's email
   * @param callback - function(err, data)
   */
  async getId(provider, token) {
    let params;
    const p = this.normalizeProvider(provider, token);

    if (p.isDeveloper) {
      params = {
        IdentityPoolId: this.config.COGNITO_IDENTITY_POOL_ID,
        DeveloperUserIdentifier: p.token,
        MaxResults: 10,
      };
      logger.debug('lookupDeveloperIdentity', params);

      return this.cognitoIdentity.lookupDeveloperIdentity(params).promise();
    } else {
      const logins = {};
      logins[p.name] = p.token;

      params = {
        IdentityPoolId: this.config.COGNITO_IDENTITY_POOL_ID,
        AccountId: this.config.AWS_ACCOUNT_ID,
        Logins: logins,
      };
      logger.debug('getId', params);

      return this.cognitoIdentity.getId(params).promise();
    }
  }

  async createDeveloperIdentity(token) {
    const p = this.normalizeProvider(null, token);

    const logins = {
      [p.name]: p.token,
    };

    const params = {
      IdentityPoolId: this.config.COGNITO_IDENTITY_POOL_ID,
      Logins: logins,
      //TokenDuration: 60
    };
    logger.debug('getOpenIdTokenForDeveloperIdentity', params);

    return this.cognitoIdentity
      .getOpenIdTokenForDeveloperIdentity(params)
      .promise();
  }

  putPasswordCognito(identityId, password) {
    const p = encryptPassword(password);
    return this.updateRecords(
      identityId,
      null,
      { password: p },
      null,
    );
  }

  normalizeProvider(providerName, token) {
    let isDeveloper = false;
    let cognitoProviderName = providerName;
    let prefixedToken = token;

    if (providerName === 'google') {
      cognitoProviderName = 'accounts.google.com';
    } else if (providerName === 'facebook') {
      cognitoProviderName = 'graph.facebook.com';
    } else if (providerName === 'amazon') {
      cognitoProviderName = 'www.amazon.com';
    } else if (providerName === 'twitter') {
      cognitoProviderName = 'api.twitter.com';
    } else {
      cognitoProviderName = this.config.COGNITO_DEVELOPER_PROVIDER_NAME;
      isDeveloper = true;
      if (providerName && token) {
        prefixedToken = providerName + this.config.COGNITO_SEPARATOR + token;
      }
    }
    return {
      name: cognitoProviderName,
      isDeveloper: isDeveloper,
      token: prefixedToken,
    };
  }

  async updateRecords(identityId, dataCreate, dataReplace, dataRemove) {
    const params = {
      IdentityPoolId: this.config.COGNITO_IDENTITY_POOL_ID,
      IdentityId: identityId,
      DatasetName: this.config.COGNITO_DATASET_NAME,
    };
    logger.debug('listRecords', params);
    let dataRecords;
    try {
      dataRecords = await this.cognitoSync.listRecords(params).promise();
    } catch (e) {
      return { statusCode: 404, body: JSON.stringify({ error: e }) };
    }

    let key;
    const recordPatches = [];

    for (key in dataCreate) {
      let record = _.find(dataRecords.Records, function(r) {
        return r.Key === key;
      });

      if (!record) {
        recordPatches.push({
          Op: 'replace',
          SyncCount: 0,
          Key: key,
          Value: dataCreate[key],
        });
      }
    }

    for (key in dataReplace) {
      let record = _.find(dataRecords.Records, function(r) {
        return r.Key === key;
      });
      recordPatches.push({
        Op: 'replace',
        SyncCount: record ? record.SyncCount : 0,
        Key: key,
        Value: dataReplace[key],
      });
    }

    for (key in dataRemove) {
      let record = _.find(dataRecords.Records, function(r) {
        return r.Key === key;
      });
      if (record) {
        recordPatches.push({
          Op: 'remove',
          SyncCount: record.SyncCount,
          Key: key,
          /* Value:dataRemove[key]*/
        });
      }
    }

    params.SyncSessionToken = dataRecords.SyncSessionToken;
    params.RecordPatches = recordPatches;
    logger.debug('updateRecords', params);

    try {
      await this.cognitoSync.updateRecords(params).promise();
    } catch (e) {
      logger.debug('updateRecords err', e);
    }

    return true;
  }

  async onLogin(provider, token, refreshToken, profile, name, identityId) {
    // updateRecords
    const create = {};
    const replace = {};
    const remove = {};

    if (name) create.name = name;

    if (provider) {
      replace.provider = provider;
      replace.token = token;

      if (refreshToken) replace[getRefreshTokenKey(provider)] = refreshToken;

      if (profile) replace[getProfileKey(provider)] = JSON.stringify(profile);
    } else {
      replace.provider = null;
      replace.token = null;
    }

    await this.updateRecords(identityId, create, replace, remove);

    return { id: identityId };
  }
}

module.exports = Cognito;
