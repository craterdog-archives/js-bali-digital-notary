/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
var V1 = require('./V1').V1;
var crypto = require('crypto');
var ec_pem = require('ec-pem');


var V1Public = {

    verify: function(encodedKey, message, encodedSignature) {
        var signature = V1.encodedToBuffer(encodedSignature);
        var publicKey = V1.encodedToBuffer(encodedKey);
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPublicKey(publicKey);
        var pem = ec_pem(curve, V1.CURVE);
        var verifier = crypto.createVerify(V1.SIGNATURE);
        verifier.update(message);
        return verifier.verify(pem.encodePublicKey(), signature);
    },

    encrypt: function(encodedKey, plaintext) {
        var publicKey = V1.encodedToBuffer(encodedKey);
        // generate and encrypt a 32-byte symmetric key
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        var seed = curve.getPublicKey();  // use the new public key as the seed
        var symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

        // encrypt the message using the symmetric key
        var iv = crypto.randomBytes(12);
        var cipher = crypto.createCipheriv(V1.CIPHER, symmetricKey, iv);
        var ciphertext = cipher.update(plaintext, 'utf8', 'base64');
        ciphertext += cipher.final('base64');
        var tag = cipher.getAuthTag();
        var aem = {
            protocol: V1.PROTOCOL,
            iv: iv,
            tag: tag,
            seed: seed,
            ciphertext: ciphertext,
            toString: function() {
                var source = V1.AEM_TEMPLATE;
                source = source.replace(/%protocol/, protocol);
                source = source.replace(/%iv/, iv);
                source = source.replace(/%tag/, tag);
                source = source.replace(/%seed/, seed);
                source = source.replace(/%ciphertext/, ciphertext);
                return source;
            }
        };
        return aem;
    }

};
exports.V1Public = V1Public;
