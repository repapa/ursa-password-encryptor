'use strict';

const expect = require('chai').expect;
const should = require("chai").should();
const encryptor = require('./encryptor');

describe('#SG Encryptor', () => {

  describe('#generateKey', () => {

    it('should generate Key', (done) => {
      encryptor.generateKey()
        .then(res => {
          should.exist(res.publicKey);
          should.exist(res.privateKey);
          done();
        });
    });

  });

  describe('#encrypt', () => {

    it('should encrypt payload with valid public key', (done) => {
      let payload = 'test data';
      encryptor.generateKey().then(res => {
        encryptor.encrypt(payload, res.publicKey).then(res => {
          should.exist(res.encryptedData);
          res.encryptedData.should.match(/^[ A-Za-z0-9_@./#&=+-]*$/);
          done();
        });
      });
    });

    it('should fail encryption because no payload', () => {
      let payload = null;
      encryptor.generateKey().then(res => {
        encryptor.encrypt(payload, res.publicKey).catch(err => {
          should.exist(err);
          // err.name.should.equal("AssertionError");
          // err.message.should.equal("payload (string) is required");
        });
      });
    });

    it('should fail encryption because no public key', () => {
      let payload = 'test data';
      let publicKey = null;
      encryptor.generateKey().then( ()=> {
        encryptor.encrypt(payload, publicKey).catch(err => {
          should.exist(err);
          // err.name.should.equal("AssertionError");
          // err.message.should.equal("publicKey (string) is required");
        });
      });
    });

    it('should fail encryption because of invalid key', () => {
      let payload = 'test data';
      let publicKey = 'invalid-public-key';
      encryptor.generateKey().then(() => {
        encryptor.encrypt(payload, publicKey).catch(err => {
          should.exist(err);
          // err.name.should.equal("Error");
          // err.message.should.equal("Not a public key.");
        });
      });
    });

  });

  describe('#decrypt', () => {

    it('should decrypt payload with valid private key', () => {
      let data = 'test data';
      return encryptor.generateKey()
        .then(key => {
          encryptor.encrypt(data, key.publicKey)
            .then(res => {
              encryptor.decrypt(res.encryptedData, key.privateKey)
                .then(res => {
                  should.exist(res.decryptedData);
                  expect(res.decryptedData).to.equal(data);
                });
            });
        });
    });

    it('should fail decryption on payload on invalid key', () => {
      let data = 'test data';
      return encryptor.generateKey()
        .then(key => {
          encryptor.encrypt(data, key.publicKey)
            .then(res => {
              let privKey = "123123123";
              encryptor.decrypt(res.encryptedData, privKey)
                .catch(err => {
                  should.exist(err);
                });
            });
        });
    });

    it('should required private key', () => {
      let data = 'test data';
      let privKey = null;
      return encryptor.generateKey()
        .then(key => {
          encryptor.encrypt(data, key.publicKey)
            .then(res => {
              encryptor.decrypt(res.encryptedData, privKey)
                .catch(err => {
                  expect(err.type).to.equal(undefined);
                  should.exist(err);
                });
            });
        });
    });

    it('should required payload', () => {
      return encryptor.generateKey()
        .then(key => {
          encryptor.decrypt(null, key.privateKey)
            .catch(err => {
              expect(err.type).to.equal(undefined);
              should.exist(err);
            });
        });
    });

  });

});

