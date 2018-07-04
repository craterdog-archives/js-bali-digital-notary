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
 * utf8 encoded character string. The string does not need to be encoded ahead
 * of time.
 * 
 * @param {String} string The (character or binary) string to be hashed.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The resulting binary hash string.
 */
exports.generateHash = function(string, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var hasher = forge.sha512.create();
            hasher.update(string);
            var hashBytes = hasher.digest().getBytes();
            return hashBytes;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This function generates a new 2048 bit RSA public/private key pair.
 * 
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {keypair} The new key pair.
 */
exports.generateKeyPair = function(optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var keypair = forge.rsa.generateKeyPair({bits: 2048});
            return keypair;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This function exports a public key into a PEM encoded string.
 * 
 * @param {PublicKey} publicKey The public key to be encoded.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The PEM encoded string.
 */
exports.exportPublicKey = function(publicKey, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var pem = forge.pki.publicKeyToPem(publicKey);
            return pem;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This function imports a public key from a PEM encoded string.
 * 
 * @param {String} pem The PEM encoded string.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {PublicKey} The corresponding public key.
 */
exports.importPublicKey = function(pem, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var publicKey = forge.pki.publicKeyFromPem(pem);
            return publicKey;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This function exports a private key into a PEM encoded string.
 * 
 * @param {PrivateKey} privateKey The private key to be encoded.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The PEM encoded string.
 */
exports.exportPrivateKey = function(privateKey, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var pem = forge.pki.privateKeyToPem(privateKey);
            return pem;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This function imports a private key from a PEM encoded string.
 * 
 * @param {String} pem The PEM encoded string.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {PrivateKey} The corresponding private key.
 */
exports.importPrivateKey = function(pem, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var privateKey = forge.pki.privateKeyFromPem(pem);
            return privateKey;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This function digitally signs a string using a private key. The resulting
 * signature can be verified using the <code>signatureIsValid()</code> function.
 * 
 * @param {PrivateKey} privateKey The private key to be used to sign the string.
 * @param {String} string The (character or binary) string to be digitally signed.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The binary string containing the signature bytes.
 */
exports.signString = function(privateKey, string, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var hasher = forge.sha512.create();
            hasher.update(string);
            var signer = forge.pss.create({
                md: forge.sha512.create(),
                mgf: forge.mgf1.create(forge.sha512.create()),
                saltLength: 20
            });
            var signatureBytes = privateKey.sign(hasher, signer);
            return signatureBytes;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This function verifies a digital signature generated using the <code>signString</code>
 * function and a private key. The corresponding public key is used to verify the digital
 * signature against the original string.
 * 
 * @param {PublicKey} publicKey The public key associated with the private key that was
 * used to sign the string.
 * @param {String} string The original (character or binary) string that was signed.
 * @param {String} signatureBytes The digital signature generated for the string.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {boolean} Whether or not the signature is valid.
 */
exports.signatureIsValid = function(publicKey, string, signatureBytes, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            var hasher = forge.sha512.create();
            hasher.update(string);
            var hash = hasher.digest().getBytes();
            var signer = forge.pss.create({
                md: forge.sha512.create(),
                mgf: forge.mgf1.create(forge.sha512.create()),
                saltLength: 20
            });
            var isValid = publicKey.verify(hash, signatureBytes, signer);
            return isValid;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + optionalVersion);
    }
};


/**
 * This function generates a random secret key and uses it to encrypt a message.  The
 * random secret key is then encrypted using the public key and an authenticated
 * encrypted message is returned.
 * 
 * @param {PublicKey} publicKey The public key to be used to encrypt a symmetric key
 * that is used to encrypt the message.
 * @param {String} message The message to be encrypted.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {Object} The authenticated encrypted message.
 */
exports.encryptMessage = function(publicKey, message, optionalVersion) {
    var version = optionalVersion || 'v1';
    switch(version) {
        case 'v1':
            // generate and encrypt a 16-byte secret key
            var kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
            var kem = forge.kem.rsa.create(kdf1);
            var result = kem.encrypt(publicKey, 16);
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


/**
 * This function decrypts an authenticated encrypted message using the private key
 * that is associated with the public key that was used to encrypt a random secret key
 * that was used to encrypt a message. The decrypted message is returned.
 * 
 * @param {PrivateKey} privateKey The private key associated with the public key that
 * was used to encrypt the secret key used to encrypt the message.
 * @param {Object} authenticatedMessage The authenticated encrypted message.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {String} The decrypted message.
 */
exports.decryptMessage = function(privateKey, authenticatedMessage, optionalVersion) {
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
            var key = kem.decrypt(privateKey, encryptedSeed, 16);
 
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
