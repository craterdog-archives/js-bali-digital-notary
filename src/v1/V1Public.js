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

/*
 * This module defines a library of cryptographic functions that involve the use of a
 * public key. The public key is associated with a private key that is maintained
 * within a hardware security module (HSM).
 */
var crypto = require('crypto');
var ec_pem = require('ec-pem');
var bali = require('bali-document-notation');
var V1 = require('./V1');


/**
 * This function uses the specified base 32 encoded public key to determine whether
 * or not the specified base 32 encoded digital signature was generated using the
 * corresponding private key on the specified message.
 * 
 * @param {Binary} publicKey The base 32 encoded public key.
 * @param {String} message The digitally signed message.
 * @param {Binary} signature The digital signature generated using the private key.
 * @returns {Boolean} Whether or not the digital signature is valid.
 */
exports.verify = function(publicKey, message, signature) {
    signature = signature.getBuffer();
    publicKey = publicKey.getBuffer();
    var curve = crypto.createECDH(V1.CURVE);
    curve.setPublicKey(publicKey);
    var pem = ec_pem(curve, V1.CURVE);
    var verifier = crypto.createVerify(V1.SIGNATURE);
    verifier.update(message);
    return verifier.verify(pem.encodePublicKey(), signature);
};


/**
 * This function uses the specified base 32 encoded public key to encrypt the specified
 * plaintext message. The result is an authenticated encrypted message (AEM) object that
 * can only be decrypted using the associated private key.
 * 
 * @param {Binary} publicKey The base 32 encoded public key to use for encryption.
 * @param {String} message The plaintext message to be encrypted.
 * @returns {Object} An authenticated encrypted message object.
 */
exports.encrypt = function(publicKey, message) {
    publicKey = publicKey.getBuffer();
    // generate and encrypt a 32-byte symmetric key
    var curve = crypto.createECDH(V1.CURVE);
    curve.generateKeys();
    var seed = curve.getPublicKey();  // use the new public key as the seed
    var symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

    // encrypt the message using the symmetric key
    var iv = crypto.randomBytes(12);
    var cipher = crypto.createCipheriv(V1.CIPHER, symmetricKey, iv);
    var ciphertext = cipher.update(message, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    var auth = cipher.getAuthTag();

    // construct the authenticated encrypted message (AEM)
    var aem = new bali.Catalog();
    aem.setValue('$protocol', V1.PROTOCOL);
    aem.setValue('$iv', new bali.Binary(iv));
    aem.setValue('$auth', new bali.Binary(auth));
    aem.setValue('$seed', new bali.Binary(seed));
    aem.setValue('$ciphertext', new bali.Binary(ciphertext));

    return aem;
};
