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
var codex = require('bali-document-notation/utilities/EncodingUtilities');
var crypto = require('crypto');
var ec_pem = require('ec-pem');


var V1Private = {

    generate: function() {
        V1Private.tag = codex.randomTag();
        V1Private.version = 'v1';
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        V1Private.privateKey = curve.getPrivateKey();
        V1Private.publicKey = curve.getPublicKey();
        var publicKey = V1.bufferToEncoded(V1Private.publicKey, '    ');
        // sign with new key
        var certificate = V1Private.certify(V1Private.tag, V1Private.version, publicKey);
        V1Private.reference = V1.cite(V1Private.tag, V1Private.version, certificate);
        return certificate;
    },

    regenerate: function() {
        var nextVersion = 'v' + (Number(V1Private.version.slice(1)) + 1);
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        var newPublicKey = V1.bufferToEncoded(curve.getPublicKey(), '    ');
        // sign with old key
        var certificate = V1Private.certify(V1Private.tag, nextVersion, newPublicKey);
        // sign with new key
        V1Private.version = nextVersion;
        V1Private.privateKey = curve.getPrivateKey();
        V1Private.publicKey = curve.getPublicKey();
        certificate += V1.cite(V1Private.tag, nextVersion, certificate);
        certificate += ' ' + V1Private.sign(certificate) + '\n';
        V1Private.reference = V1.cite(V1Private.tag, nextVersion, certificate);
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
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(V1Private.privateKey);
        var pem = ec_pem(curve, V1.CURVE);
        var signer = crypto.createSign(V1.SIGNATURE);
        signer.update(document);
        var signature = signer.sign(pem.encodePrivateKey());
        var encodedSignature = V1.bufferToEncoded(signature);
        return encodedSignature;
    },

    certify: function(tag, version, publicKey) {
        var certificate = V1.CERTIFICATE_TEMPLATE;
        certificate = certificate.replace(/%protocol/, V1.PROTOCOL);
        certificate = certificate.replace(/%tag/, tag);
        certificate = certificate.replace(/%version/, version);
        certificate = certificate.replace(/%publicKey/, publicKey);
        certificate += V1.cite(tag, version);  // no document, self-signed
        certificate += ' ' + V1Private.sign(certificate) + '\n';
        return certificate;
    },

    decrypt: function(aem) {
        // decrypt the 32-byte symmetric key
        var seed = aem.seed;
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(V1Private.privateKey);
        var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

        // decrypt the ciphertext using the symmetric key
        var decipher = crypto.createDecipheriv(V1.CIPHER, symmetricKey, aem.iv);
        decipher.setAuthTag(aem.tag);
        var plaintext = decipher.update(aem.ciphertext, 'base64', 'utf8');
        plaintext += decipher.final('utf8');
        return plaintext;
    }
};
exports.V1Private = V1Private;
