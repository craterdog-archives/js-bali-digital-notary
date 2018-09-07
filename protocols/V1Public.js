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
var V1 = require('./V1');
var crypto = require('crypto');
var ec_pem = require('ec-pem');


exports.verify = function(encodedKey, message, encodedSignature) {
    var signature = V1.encodedToBuffer(encodedSignature);
    var publicKey = V1.encodedToBuffer(encodedKey);
    var curve = crypto.createECDH(V1.CURVE);
    curve.setPublicKey(publicKey);
    var pem = ec_pem(curve, V1.CURVE);
    var verifier = crypto.createVerify(V1.SIGNATURE);
    verifier.update(message);
    return verifier.verify(pem.encodePublicKey(), signature);
};

exports.encrypt = function(encodedKey, plaintext) {
    var publicKey = V1.encodedToBuffer(encodedKey);
    // generate and encrypt a 32-byte symmetric key
    var curve = crypto.createECDH(V1.CURVE);
    curve.generateKeys();
    var seed = curve.getPublicKey();  // use the new public key as the seed
    var symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

    // encrypt the message using the symmetric key
    var iv = crypto.randomBytes(12);
    var cipher = crypto.createCipheriv(V1.CIPHER, symmetricKey, iv);
    var ciphertext = cipher.update(plaintext, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    var auth = cipher.getAuthTag();

    // construct the authenticated encrypted message
    var aem = {
        protocol: V1.PROTOCOL,
        iv: iv,
        auth: auth,
        seed: seed,
        ciphertext: ciphertext,

        toString: function() {
            var string = this.toSource();
            return string;
        },

        toSource: function(padding) {
            padding = padding ? padding : '';
            var source =  '[\n' +
                padding + '    $protocol: %protocol\n' +
                padding + '    $iv: %iv\n' +
                padding + '    $auth: %auth\n' +
                padding + '    $seed: %seed\n' +
                padding + '    $ciphertext: %ciphertext\n' +
                padding + ']\n';
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%iv/, V1.bufferToEncoded(this.iv, padding + '    '));
            source = source.replace(/%auth/, V1.bufferToEncoded(this.auth, padding + '    '));
            source = source.replace(/%seed/, V1.bufferToEncoded(this.seed, padding + '    '));
            source = source.replace(/%ciphertext/, V1.bufferToEncoded(this.ciphertext, padding + '    '));
            return source;
        }
    };

    return aem;
};
