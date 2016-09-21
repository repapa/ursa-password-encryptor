'use strict';

const ursa = require('ursa');
const Promise = require('bluebird');
const assert = require('assert-plus');

module.exports.generateKey = () => {
  return Promise.try(() => {
    const key = ursa.generatePrivateKey(1024, 65537);
    return Promise.resolve({
      'publicKey': key.toPublicPem().toString('utf8')
      , 'privateKey': key.toPrivatePem().toString('utf8')
    });
  });
}

module.exports.encrypt = (payload, publicKey) => {
  return Promise.try(() => {
    assert.string(payload, "payload");
    assert.string(publicKey, "publicKey");
    const ursaPublicKey = ursa.coercePublicKey(publicKey);
    //check if valid public key
    if (ursa.isKey(ursaPublicKey)) {
      const res = { 'encryptedData': ursaPublicKey.encrypt(payload, 'utf8', 'base64', ursa.RSA_PKCS1_PADDING) }
      return Promise.resolve(res);
    }
  }).catch(err => {
    throw err;
  });
}


module.exports.decrypt = (payload, privateKey) => {
  return Promise.try(() => {
    assert.string(payload, "payload");
    assert.string(privateKey, "privateKey");
    const privKeyDecryptor = ursa.coercePrivateKey(privateKey);
    return Promise.resolve({ 'decryptedData': privKeyDecryptor.decrypt(payload, 'base64', 'utf8', ursa.RSA_PKCS1_PADDING) });
  }).catch(err => {
    throw err;
  });
}


