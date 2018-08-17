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

    KEY_TEMPLATE:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $publicKey: %publicKey\n' +
        '    $citation: %citation\n' +
        ']\n',

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

    citation: function(tag, version, hash) {
        var citation = V1.CITATION_TEMPLATE;
        citation = citation.replace(/%protocol/, V1.PROTOCOL);
        citation = citation.replace(/%tag/, tag);
        citation = citation.replace(/%version/, version);
        citation = citation.replace(/%hash/, hash);
        return citation;
    },

    certificate: function(tag, version, publicKey) {
        var certificate = V1.CERTIFICATE_TEMPLATE;
        certificate = certificate.replace(/%protocol/, V1.PROTOCOL);
        certificate = certificate.replace(/%tag/, tag);
        certificate = certificate.replace(/%version/, version);
        certificate = certificate.replace(/%publicKey/, publicKey);
        return certificate;
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

    generate: function(notaryKey) {
        var tag;
        var version;
        if (notaryKey) {
            // regenerate existing notary key
            tag = notaryKey.tag;
            version = 'v' + (Number(notaryKey.version.slice(1)) + 1);
        } else {
            // generate a new notary key
            tag = codex.randomTag();
            version = 'v1';
        }
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        var publicKey = bufferToEncoded(curve.getPublicKey());
        notaryKey = new V1.NotaryKey(tag, version, publicKey);
        // NOTE: cannot create the citation yet without the notarized certificate
        var keyId = tag + version;
        V1.keys.set(keyId, curve.getPrivateKey());
        return notaryKey;
    },

    recreate: function(tag, version, publicKey, citation) {
        var notaryKey = new V1.NotaryKey(tag, version, publicKey);
        notaryKey.citation = citation;
        return notaryKey;
    },

    forget: function(notaryKey) {
        var keyId = notaryKey.tag + notaryKey.version;
        V1.keys.delete(keyId);
    },

    sign: function(notaryKey, message) {
        var keyId = notaryKey.tag + notaryKey.version;
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(V1.keys.get(keyId));
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
            version: V1.PROTOCOL,
            iv: iv,
            tag: tag,
            seed: seed,
            ciphertext: ciphertext
        };
        return aem;
    },

    decrypt: function(notaryKey, aem) {
        var keyId = notaryKey.tag + notaryKey.version;
        // decrypt the 32-byte symmetric key
        var seed = aem.seed;
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(V1.keys.get(keyId));
        var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

        // decrypt the ciphertext using the symmetric key
        var decipher = crypto.createDecipheriv(V1.CIPHER, symmetricKey, aem.iv);
        decipher.setAuthTag(aem.tag);
        var plaintext = decipher.update(aem.ciphertext, 'base64', 'utf8');
        plaintext += decipher.final('utf8');
        return plaintext;
    },

    NotaryKey: function(tag, version, publicKey) {
        this.protocol = V1.PROTOCOL;
        this.tag = tag;
        this.version = version;
        this.publicKey = publicKey;
        var citation = V1.cite(tag, version);
        this.citation = citation;

        this.toString = function() {
            var source = V1.KEY_TEMPLATE;
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%publicKey/, this.publicKey);
            source = source.replace(/%citation/, this.citation);
            return source;
        };

        return this;
    }
};
exports.V1 = V1;


function encodedToBuffer(encoded) {
    var base32 = encoded.slice(1, -1);  // remove the "'"s
    buffer = codex.base32Decode(base32);
    return buffer;
}

function bufferToEncoded(buffer) {
    var base32 = codex.base32Encode(buffer, '        ');
    var encoded = "'" + base32 + "\n    '";  // add in the "'"s
    return encoded;
}
