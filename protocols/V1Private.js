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


var V1Private = {

    PROTOCOL: 'v1',
    CURVE: 'secp521r1',
    DIGEST: 'sha512',
    SIGNATURE: 'ecdsa-with-SHA1',
    CIPHER: 'aes-256-gcm',

    REFERENCE_TEMPLATE: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version]>',

    CITATION_TEMPLATE: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>',

    CERTIFICATE_TEMPLATE:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $publicKey: %publicKey\n' +
        ']\n',

    generate: function() {
        V1Private.tag = codex.randomTag();
        V1Private.version = 'v1';
        var curve = crypto.createECDH(V1Private.CURVE);
        curve.generateKeys();
        V1Private.privateKey = curve.getPrivateKey();
        V1Private.publicKey = curve.getPublicKey();
        var publicKey = bufferToEncoded(V1Private.publicKey, '    ');
        // sign with new key
        var certificate = certify(V1Private.tag, V1Private.version, publicKey);
        V1Private.reference = cite(V1Private.tag, V1Private.version, certificate);
        return certificate;
    },

    regenerate: function() {
        var nextVersion = 'v' + (Number(V1Private.version.slice(1)) + 1);
        var curve = crypto.createECDH(V1Private.CURVE);
        curve.generateKeys();
        var newPublicKey = bufferToEncoded(curve.getPublicKey(), '    ');
        // sign with old key
        var certificate = certify(V1Private.tag, nextVersion, newPublicKey);
        // sign with new key
        V1Private.version = nextVersion;
        V1Private.privateKey = curve.getPrivateKey();
        V1Private.publicKey = curve.getPublicKey();
        certificate += cite(V1Private.tag, nextVersion, certificate);
        certificate += ' ' + V1Private.sign(certificate) + '\n';
        V1Private.reference = cite(V1Private.tag, nextVersion, certificate);
        return certificate;
    },

    forget: function() {
        V1Private.tag = undefined;
        V1Private.version = undefined;
        V1Private.privateKey = undefined;
        V1Private.publicKey = undefined;
        V1Private.reference = undefined;
    },

    sign: function(document) {
        var curve = crypto.createECDH(V1Private.CURVE);
        curve.setPrivateKey(V1Private.privateKey);
        var pem = ec_pem(curve, V1Private.CURVE);
        var signer = crypto.createSign(V1Private.SIGNATURE);
        signer.update(document);
        var signature = signer.sign(pem.encodePrivateKey());
        var encodedSignature = bufferToEncoded(signature);
        return encodedSignature;
    },

    decrypt: function(aem) {
        // decrypt the 32-byte symmetric key
        var seed = aem.seed;
        var curve = crypto.createECDH(V1Private.CURVE);
        curve.setPrivateKey(V1Private.privateKey);
        var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

        // decrypt the ciphertext using the symmetric key
        var decipher = crypto.createDecipheriv(V1Private.CIPHER, symmetricKey, aem.iv);
        decipher.setAuthTag(aem.tag);
        var plaintext = decipher.update(aem.ciphertext, 'base64', 'utf8');
        plaintext += decipher.final('utf8');
        return plaintext;
    }
};
exports.V1Private = V1Private;


function bufferToEncoded(buffer, padding) {
    if (!padding) padding = '';
    var base32 = codex.base32Encode(buffer, padding + '    ');
    var encoded = "'" + base32 + "\n" + padding + "'";  // add in the "'"s
    return encoded;
}

function cite(tag, version, document) {
    var reference = document ? V1Private.CITATION_TEMPLATE : V1Private.REFERENCE_TEMPLATE;
    reference = reference.replace(/%protocol/, V1Private.PROTOCOL);
    reference = reference.replace(/%tag/, tag);
    reference = reference.replace(/%version/, version);
    if (document) {
        var hasher = crypto.createHash(V1Private.DIGEST);
        hasher.update(document);
        var digest = hasher.digest();
        var encodedDigest = "'" + codex.base32Encode(digest).replace(/\s+/g, '') + "'";
        reference = reference.replace(/%digest/, encodedDigest);
    }
    return reference;
}

function certify(tag, version, publicKey) {
    var certificate = V1Private.CERTIFICATE_TEMPLATE;
    certificate = certificate.replace(/%protocol/, V1Private.PROTOCOL);
    certificate = certificate.replace(/%tag/, tag);
    certificate = certificate.replace(/%version/, version);
    certificate = certificate.replace(/%publicKey/, publicKey);
    certificate += cite(tag, version);  // no document, self-signed
    certificate += ' ' + V1Private.sign(certificate) + '\n';
    return certificate;
}
