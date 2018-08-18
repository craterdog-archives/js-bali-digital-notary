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


var V1 = {

    PROTOCOL: 'v1',
    CURVE: 'secp521r1',
    DIGEST: 'sha512',
    SIGNATURE: 'ecdsa-with-SHA1',
    CIPHER: 'aes-256-gcm',

    CERTIFICATE_TEMPLATE:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $publicKey: %publicKey\n' +
        ']\n',

    REFERENCE_TEMPLATE: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version]>',

    CITATION_TEMPLATE: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$hash:%hash]>',

    keys: new Map(),

    digest: function(message) {
        var hasher = crypto.createHash(V1.DIGEST);
        hasher.update(message);
        var digest = hasher.digest();
        var encodedDigest = bufferToEncoded(digest).replace(/\s+/g, '');  // strip out any whitespace
        return encodedDigest;
    },

    cite: function(tag, version, document) {
        var citation = document ? V1.CITATION_TEMPLATE : V1.REFERENCE_TEMPLATE;
        citation = citation.replace(/%protocol/, V1.PROTOCOL);
        citation = citation.replace(/%tag/, tag);
        citation = citation.replace(/%version/, version);
        if (document) {
            citation = citation.replace(/%hash/, V1.digest(document));
        }
        return citation;
    },

    generate: function() {
        V1.tag = codex.randomTag();
        V1.version = 'v1';
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        V1.privateKey = curve.getPrivateKey();
        V1.publicKey = curve.getPublicKey();
        var publicKey = bufferToEncoded(V1.publicKey, '    ');
        // sign with new key
        var certificate = certify(V1.tag, V1.version, publicKey);
        V1.citation = V1.cite(V1.tag, V1.version, certificate);
        return certificate;
    },

    regenerate: function() {
        var nextVersion = 'v' + (Number(V1.version.slice(1)) + 1);
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        var newPublicKey = bufferToEncoded(curve.getPublicKey(), '    ');
        // sign with old key
        var certificate = certify(V1.tag, nextVersion, newPublicKey);
        // sign with new key
        V1.version = nextVersion;
        V1.privateKey = curve.getPrivateKey();
        V1.publicKey = curve.getPublicKey();
        certificate += V1.cite(V1.tag, nextVersion, certificate);
        certificate += ' ' + V1.sign(certificate) + '\n';
        V1.citation = V1.cite(V1.tag, nextVersion, certificate);
        return certificate;
    },

    forget: function() {
        V1.tag = undefined;
        V1.version = undefined;
        V1.privateKey = undefined;
        V1.publicKey = undefined;
        V1.citation = undefined;
    },

    sign: function(message) {
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(V1.privateKey);
        var pem = ec_pem(curve, V1.CURVE);
        var signer = crypto.createSign(V1.SIGNATURE);
        signer.update(message);
        var signature = signer.sign(pem.encodePrivateKey());
        var encodedSignature = bufferToEncoded(signature);
        return encodedSignature;
    },

    verify: function(encodedKey, message, encodedSignature) {
        var signature = encodedToBuffer(encodedSignature);
        var publicKey = encodedToBuffer(encodedKey);
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPublicKey(publicKey);
        var pem = ec_pem(curve, V1.CURVE);
        var verifier = crypto.createVerify(V1.SIGNATURE);
        verifier.update(message);
        return verifier.verify(pem.encodePublicKey(), signature);
    },

    encrypt: function(encodedKey, plaintext) {
        var publicKey = encodedToBuffer(encodedKey);
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
            ciphertext: ciphertext
        };
        return aem;
    },

    decrypt: function(aem) {
        // decrypt the 32-byte symmetric key
        var seed = aem.seed;
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(V1.privateKey);
        var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

        // decrypt the ciphertext using the symmetric key
        var decipher = crypto.createDecipheriv(V1.CIPHER, symmetricKey, aem.iv);
        decipher.setAuthTag(aem.tag);
        var plaintext = decipher.update(aem.ciphertext, 'base64', 'utf8');
        plaintext += decipher.final('utf8');
        return plaintext;
    }
};
exports.V1 = V1;


function encodedToBuffer(encoded) {
    var base32 = encoded.slice(1, -1);  // remove the "'"s
    buffer = codex.base32Decode(base32);
    return buffer;
}

function bufferToEncoded(buffer, padding) {
    if (!padding) padding = '';
    var base32 = codex.base32Encode(buffer, padding + '    ');
    var encoded = "'" + base32 + "\n" + padding + "'";  // add in the "'"s
    return encoded;
}

function certify(tag, version, publicKey) {
    var certificate = V1.CERTIFICATE_TEMPLATE;
    certificate = certificate.replace(/%protocol/, V1.PROTOCOL);
    certificate = certificate.replace(/%tag/, tag);
    certificate = certificate.replace(/%version/, version);
    certificate = certificate.replace(/%publicKey/, publicKey);
    certificate += V1.cite(tag, version);  // no document, self-signed
    certificate += ' ' + V1.sign(certificate) + '\n';
    return certificate;
}
