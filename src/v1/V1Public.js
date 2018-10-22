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
function verify(publicKey, message, signature) {
    signature = signature.getBuffer();
    publicKey = publicKey.getBuffer();
    var curve = crypto.createECDH(V1.CURVE);
    curve.setPublicKey(publicKey);
    var pem = ec_pem(curve, V1.CURVE);
    var verifier = crypto.createVerify(V1.SIGNATURE);
    verifier.update(message);
    return verifier.verify(pem.encodePublicKey(), signature);
}
exports.verify = verify;


/**
 * This function uses the specified base 32 encoded public key to encrypt the specified
 * plaintext message. The result is an authenticated encrypted message (AEM) object that
 * can only be decrypted using the associated private key.
 * 
 * @param {Binary} publicKey The base 32 encoded public key to use for encryption.
 * @param {String} message The plaintext message to be encrypted.
 * @returns {Object} An authenticated encrypted message object.
 */
function encrypt(publicKey, message) {
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
    var aem = {
        protocol: V1.PROTOCOL,   // the version of the Bali security protocol used
        iv: iv,                  // the initialization vector
        auth: auth,              // the message authentication code
        seed: seed,              // the seed for the symmetric key
        ciphertext: ciphertext,  // the resulting ciphertext

        /**
         * This method implements the standard toString() method for the AEM object by
         * delegating to the toSource() method which produces a canonical Bali source
         * code string for the AEM object.
         * 
         * @returns {String} A canonical Bali source code string for the AEM object.
         */
        toString: function() {
            var string = this.toSource();
            return string;
        },

        /**
         * This method returns the canonical Bali source code representation for the AEM
         * object. It allows an optional indentation to be included which will be prepended
         * to each indented line of the resulting string.
         * 
         * @param {String} indentation A string of spaces to be used as additional indentation
         * for each line within the resulting string.
         * @returns {String} A canonical Bali source code string for the AEM object.
         */
        toSource: function(indentation) {
            indentation = indentation ? indentation : '';
            var source =  '[\n' +
                indentation + '    $protocol: %protocol\n' +
                indentation + '    $iv: %iv\n' +
                indentation + '    $auth: %auth\n' +
                indentation + '    $seed: %seed\n' +
                indentation + '    $ciphertext: %ciphertext\n' +
                indentation + ']\n';
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%iv/, new bali.Binary(this.iv).toSource(indentation + '    '));
            source = source.replace(/%auth/, new bali.Binary(this.auth).toSource(indentation + '    '));
            source = source.replace(/%seed/, new bali.Binary(this.seed).toSource(indentation + '    '));
            source = source.replace(/%ciphertext/, new bali.Binary(this.ciphertext).toSource(indentation + '    '));
            return source;
        }
    };

    return aem;
}
exports.encrypt = encrypt;
