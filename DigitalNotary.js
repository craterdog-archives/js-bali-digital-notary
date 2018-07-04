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
 * @param {string} string The (character or binary) string to be hashed.
 * @param {string} optionalVersion An optional library version string for the
 * implementation (e.g. '1', '1.3', '2', etc.).  The default version is '1'.
 * @returns {string} The resulting binary hash string.
 */
exports.sha512Hash = function(string, optionalVersion) {
    if (optionalVersion === undefined) {
        optionalVersion = '1';
    }
    switch(optionalVersion) {
        case '1':
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
 * @param {string} optionalVersion An optional library version string for the
 * implementation (e.g. '1', '1.3', '2', etc.).  The default version is '1'.
 * @returns {keypair} The new key pair.
 */
exports.generateKeyPair = function(optionalVersion) {
    if (optionalVersion === undefined) {
        optionalVersion = '1';
    }
    switch(optionalVersion) {
        case '1':
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
 * @returns {String} The PEM encoded string.
 */
exports.exportPublicKey = function(publicKey) {
    var pem = forge.pki.publicKeyToPem(publicKey);
    return pem;
};


/**
 * This function imports a public key from a PEM encoded string.
 * 
 * @param {String} pem The PEM encoded string.
 * @returns {PublicKey} The corresponding public key.
 */
exports.importPublicKey = function(pem) {
    var publicKey = forge.pki.publicKeyFromPem(pem);
    return publicKey;
};


/**
 * This function exports a private key into a PEM encoded string.
 * 
 * @param {PrivateKey} privateKey The private key to be encoded.
 * @returns {String} The PEM encoded string.
 */
exports.exportPrivateKey = function(privateKey) {
    var pem = forge.pki.privateKeyToPem(privateKey);
    return pem;
};


/**
 * This function imports a private key from a PEM encoded string.
 * 
 * @param {String} pem The PEM encoded string.
 * @returns {PrivateKey} The corresponding private key.
 */
exports.importPrivateKey = function(pem) {
    var privateKey = forge.pki.privateKeyFromPem(pem);
    return privateKey;
};


/**
 * This function digitally signs a string using a private key. The resulting
 * signature can be verified using the <code>signatureIsValid()</code> function.
 * 
 * @param {PrivateKey} privateKey The private key to be used to sign the string.
 * @param {string} string The (character or binary) string to be digitally signed.
 * @param {string} optionalVersion An optional library version string for the
 * implementation (e.g. '1', '1.3', '2', etc.).  The default version is '1'.
 * @returns {string} The binary string containing the signature bytes.
 */
exports.signString = function(privateKey, string, optionalVersion) {
    if (optionalVersion === undefined) {
        optionalVersion = '1';
    }
    switch(optionalVersion) {
        case '1':
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
 * @param {string} string The original (character or binary) string that was signed.
 * @param {string} signatureBytes The digital signature generated for the string.
 * @param {string} optionalVersion An optional library version string for the
 * implementation (e.g. '1', '1.3', '2', etc.).  The default version is '1'.
 * @returns {boolean} Whether or not the signature is valid.
 */
exports.signatureIsValid = function(publicKey, string, signatureBytes, optionalVersion) {
    if (optionalVersion === undefined) {
        optionalVersion = '1';
    }
    switch(optionalVersion) {
        case '1':
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


exports.encryptBytes = function(publicKey, bytes) {
    throw new Error('SECURITY: Not yet implemented...');
};


exports.decryptBytes = function(privateKey, bytes) {
    throw new Error('SECURITY: Not yet implemented...');
};
