'use strict';

const encryptor = require('../utils/encryptor');
const ursa = require('ursa');
const Promise = require('bluebird');

module.exports = function (Encryption) {

  Encryption.remoteMethod(
    'encryptPassword', {
      description: "Encrypt password for QA environment only",
      http: { verb: 'post', path: '/passwords/encrypt' },
      accepts: [
        {
          description: 'password to be encrypted',
          arg: 'password',
          type: 'string'
        },
        {
          description: 'publickey for encryption',
          arg: 'publicKey',
          type: 'string'
        }
      ],

      returns: { arg: 'encryptedPassword', type: 'string' }
    }
  );

  Encryption.encryptPassword = (password, publicKey) => {
    return Promise.coroutine(function* () {
      const logger = Encryption.app.logger;
      try {
        if (typeof password !== 'string' || !password.trim() || password.length > 25) {
          throw { error: Error('INVALID_ARGUMENT'), meta: { details: 'password is not valid' } };
        }

        if (typeof publicKey !== 'string' || !publicKey.trim()) {
          throw { error: Error('INVALID_ARGUMENT'), meta: { details: 'public key is not valid' } };
        }

        try {
          let pubKey = ursa.createPublicKey(publicKey);
          ursa.assertPublicKey(pubKey);
        } catch (e) {
          throw { error: Error('INVALID_ARGUMENT'), meta: { details: 'public key is not valid' }, src: e };
        }

        let data = null;
        try {
          data = yield encryptor.encrypt(password, publicKey);
        } catch (e) {
          throw { error: Error('ENCRYPTION_ERROR'), src: e };
        }
        return Promise.resolve(data.encryptedData);
      } catch (err) {
        err.logger = logger;
        return Promise.reject(err);
      }
    })();

  }

};
