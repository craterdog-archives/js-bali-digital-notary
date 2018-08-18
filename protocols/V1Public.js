/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
var codex = require('bali-document-notation/utilities/EncodingUtilities');
var crypto = require('crypto');
var ec_pem = require('ec-pem');


var V1Public = {

    PROTOCOL: 'v1',
    CURVE: 'secp521r1',
    DIGEST: 'sha512',
    SIGNATURE: 'ecdsa-with-SHA1',
    CIPHER: 'aes-256-gcm',

    REFERENCE_TEMPLATE: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version]>',

    CITATION_TEMPLATE: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>',

    AEM_TEMPLATE:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $iv: %iv\n' +
        '    $tag: %tag\n' +
        '    $seed: %seed\n' +
        '    $ciphertext: %ciphertext\n' +
        ']\n',

    digest: function(message) {
        var hasher = crypto.createHash(V1Public.DIGEST);
        hasher.update(message);
        var digest = hasher.digest();
        var encodedDigest = "'" + codex.base32Encode(digest).replace(/\s+/g, '') + "'";
        return encodedDigest;
    },

    cite: function(tag, version, document) {
        var reference = document ? V1Public.CITATION_TEMPLATE : V1Public.REFERENCE_TEMPLATE;
        reference = reference.replace(/%protocol/, V1Public.PROTOCOL);
        reference = reference.replace(/%tag/, tag);
        reference = reference.replace(/%version/, version);
        if (document) {
            reference = reference.replace(/%digest/, V1Public.digest(document));
        }
        return reference;
    },

    verify: function(encodedKey, message, encodedSignature) {
        var signature = encodedToBuffer(encodedSignature);
        var publicKey = encodedToBuffer(encodedKey);
        var curve = crypto.createECDH(V1Public.CURVE);
        curve.setPublicKey(publicKey);
        var pem = ec_pem(curve, V1Public.CURVE);
        var verifier = crypto.createVerify(V1Public.SIGNATURE);
        verifier.update(message);
        return verifier.verify(pem.encodePublicKey(), signature);
    },

    encrypt: function(encodedKey, plaintext) {
        var publicKey = encodedToBuffer(encodedKey);
        // generate and encrypt a 32-byte symmetric key
        var curve = crypto.createECDH(V1Public.CURVE);
        curve.generateKeys();
        var seed = curve.getPublicKey();  // use the new public key as the seed
        var symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

        // encrypt the message using the symmetric key
        var iv = crypto.randomBytes(12);
        var cipher = crypto.createCipheriv(V1Public.CIPHER, symmetricKey, iv);
        var ciphertext = cipher.update(plaintext, 'utf8', 'base64');
        ciphertext += cipher.final('base64');
        var tag = cipher.getAuthTag();
        var aem = {
            protocol: V1Public.PROTOCOL,
            iv: iv,
            tag: tag,
            seed: seed,
            ciphertext: ciphertext,
            toString: function() {
                var source = V1Public.AEM_TEMPLATE;
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


function encodedToBuffer(encoded) {
    var base32 = encoded.slice(1, -1);  // remove the "'"s
    buffer = codex.base32Decode(base32);
    return buffer;
}
