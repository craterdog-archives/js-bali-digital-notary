/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
'use strict';
var forge = require('node-forge');


/**
 * This function returns a SHA-512 binary hash string of the specified
 * utf8 encoded message. The message may be binary or character data.
 * 
 * @param {String} message The (character or binary) string to be hashed.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The resulting binary hash string.
 */
exports.generateHash = function(message, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var hasher = forge.sha512.create();
            hasher.update(message);
            var hashBytes = hasher.digest().getBytes();
            return hashBytes;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This constructor creates a new notary key. If an optional PEM formatted string is
 * passed into the constructor, the key definition will be used to construct the
 * notary key. Otherwise, a new notary key and associated certificate will be
 * generated. The associated notary certificate may then be retrieved from
 * 'this.certificate'.
 * 
 * @constructor
 * @param {String} pem An optional PEM formatted string containing the notary key
 * definition. If no PEM string is passed, a new notary key will be generated.
 * @returns {NotaryKey} The notary key.
 */
function NotaryKey(pem) {
    if (pem) {
        this.key = forge.pki.privateKeyFromPem(pem);
        this.certificate = new exports.NotaryCertificate();
        this.certificate.publicKey = forge.pki.rsa.setPublicKey(this.key.n, this.key.e);
    } else {
        var keypair = forge.rsa.generateKeyPair({bits: 2048});
        this.key = keypair.privateKey;
        this.certificate = new exports.NotaryCertificate();
        this.certificate.publicKey = keypair.publicKey;
    }
    return this;
}
NotaryKey.prototype.constructor = NotaryKey;
exports.NotaryKey = NotaryKey;


/**
 * This method exports the notary key definition into a PEM encoded string.
 * 
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The PEM encoded string.
 */
NotaryKey.prototype.exportPem = function(optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var pem = forge.pki.privateKeyToPem(this.key);
            return pem;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This method generates a new notary key and associated notary certificate. It
 * uses the old notary key to notarize the new notary certificate to prove its
 * place in the certificate chain.
 * 
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {PublicKey} The new notary certificate.
 */
NotaryKey.prototype.regenerateKey = function(optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var keypair = forge.rsa.generateKeyPair({bits: 2048});
            this.key = keypair.privateKey;
            this.certificate = new exports.NotaryCertificate();
            this.certificate.publicKey = keypair.publicKey;
            return this.certificate;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This method digitally notarizes a message using the notary key. The resulting
 * notary seal can be validated using the <code>sealIsValid()</code> function.
 * 
 * @param {String} message The (character or binary) string to be digitally signed.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The binary string containing the notary seal.
 */
NotaryKey.prototype.generateSeal = function(message, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var hasher = forge.sha512.create();
            hasher.update(message);
            var signer = forge.pss.create({
                md: forge.sha512.create(),
                mgf: forge.mgf1.create(forge.sha512.create()),
                saltLength: 20
            });
            var seal = this.key.sign(hasher, signer);
            return seal;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This method decrypts an authenticated encrypted message generated using the notary
 * certificate associated with this notary key. The notary certificate generated and
 * encrypted a random secret key that was used to encrypt the message. The decrypted
 * message is returned.
 * 
 * @param {Object} authenticatedMessage The authenticated encrypted message.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The decrypted message.
 */
NotaryKey.prototype.decryptMessage = function(authenticatedMessage, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            // decompose the authenticated encrypted message
            var iv = authenticatedMessage.iv;
            var tag = authenticatedMessage.tag;
            var encryptedSeed = authenticatedMessage.encryptedSeed;
            var encryptedMessage = authenticatedMessage.encryptedMessage;

            // decrypt the 16-byte secret key
            var kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
            var kem = forge.kem.rsa.create(kdf1);
            var key = kem.decrypt(this.key, encryptedSeed, 16);
 
            // decrypt the message using the secret key
            var message;
            var decipher = forge.cipher.createDecipher('AES-GCM', key);
            decipher.start({iv: iv, tag: tag});
            decipher.update(forge.util.createBuffer(encryptedMessage));
            var authenticated = decipher.finish();
            // authenticated is false if there was a failure (eg: authentication tag didn't match)
            if(authenticated) {
               message = decipher.output.getBytes();
            }
            return message;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This constructor creates a notary certificate using a PEM formatted string
 * containing the notary certificate definition.
 * 
 * @constructor
 * @param {String} pem A PEM formatted string containing the notary certificate
 * definition. 
 * @returns {NotaryCertificate} The notary certificate.
 */
function NotaryCertificate(pem) {
    if (pem) {
        this.publicKey = forge.pki.publicKeyFromPem(pem);
    }
    return this;
}
NotaryCertificate.prototype.constructor = NotaryCertificate;
exports.NotaryCertificate = NotaryCertificate;


/**
 * This method exports the notary certificate definition into a PEM encoded string.
 * 
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The PEM encoded string.
 */
NotaryCertificate.prototype.exportPem = function(optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var pem = forge.pki.publicKeyToPem(this.publicKey);
            return pem;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This method verifies a notary seal generated using the <code>generateSeal</code>
 * method on the associated notary key. This notary certificate is used to verify the
 * notary seal against the original message.
 * 
 * used to sign the string.
 * @param {String} message The original (character or binary) string that was signed.
 * @param {String} seal The notary seal generated for the message.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {boolean} Whether or not the notary seal is valid.
 */
NotaryCertificate.prototype.sealIsValid = function(message, seal, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var hasher = forge.sha512.create();
            hasher.update(message);
            var hash = hasher.digest().getBytes();
            var signer = forge.pss.create({
                md: forge.sha512.create(),
                mgf: forge.mgf1.create(forge.sha512.create()),
                saltLength: 20
            });
            var isValid = this.publicKey.verify(hash, seal, signer);
            return isValid;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This method generates a random secret key and uses it to encrypt a message.  The
 * random secret key is then encrypted by the notary certificate and an authenticated
 * encrypted message is returned. The resulting authenticated encrypted message can
 * be decrypted using the <code>decryptMessage</code> method on the corresponding
 * notary key.
 * 
 * @param {String} message The message to be encrypted.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {Object} The authenticated encrypted message.
 */
NotaryCertificate.prototype.encryptMessage = function(message, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            // generate and encrypt a 16-byte secret key
            var kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
            var kem = forge.kem.rsa.create(kdf1);
            var result = kem.encrypt(this.publicKey, 16);
            var key = result.key;
            var encryptedSeed = result.encapsulation;
 
            // encrypt the message using the secret key
            var iv = forge.random.getBytesSync(12);
            var cipher = forge.cipher.createCipher('AES-GCM', key);
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(message));
            cipher.finish();
            var encryptedMessage = cipher.output.getBytes();
            var tag = cipher.mode.tag.getBytes();

            // return all components of the authenticated message
            return {
                iv: iv,
                tag: tag,
                encryptedSeed: encryptedSeed,
                encryptedMessage: encryptedMessage
            };
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};
