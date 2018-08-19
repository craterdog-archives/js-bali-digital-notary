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
var bali = require('bali-document-notation/BaliDocuments');
var crypto = require('crypto');
var ec_pem = require('ec-pem');
var config = require('os').homedir() + '/.bali/';
var fs = require('fs');

///////////////////////////////////////////////////////////////////////////////////////
// This module should be used for LOCAL TESTING ONLY.  It is NOT SECURE and provides //
// no guarantees on protecting access to the private key.  YOU HAVE BEEN WARNED!!!   //
///////////////////////////////////////////////////////////////////////////////////////


/**
 * This function returns the TEST software security module managing the private key
 * for the specified tag.
 * 
 * @param {String} tag The unique tag for the hardware security module.
 * @returns {Object} A proxy to the hardware security module managing the private key.
 */
exports.getNotaryKey = function(tag) {
    
    var NOTARY_TEMPLATE =
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $reference: %reference\n' +
        '    $publicKey: %publicKey\n' +
        '    $privateKey: %privateKey\n' +
        ']\n';

    // create the config directory if necessary
    if (!fs.existsSync(config)) fs.mkdirSync(config, 448);  // drwx------ permissions
    var keyFile = config + tag + '.bali';

    // read in the notary key attributes
    var protocol;
    var version;
    var reference;
    var publicKey;
    var privateKey;
    try {
        if (fs.existsSync(keyFile)) {
            // read in the notary key information
            source = fs.readFileSync(keyFile).toString();
            var document = bali.parseDocument(source);
            protocol = bali.getStringForKey(document, '$protocol');
            if (V1.PROTOCOL !== protocol) {
                throw new Error('NOTARY: The protocol for the test private key is not supported: ' + protocol);
            }
            version = bali.getStringForKey(document, '$version');
            reference = bali.getStringForKey(document, '$reference');
            publicKey = V1.encodedToBuffer(bali.getStringForKey(document, '$publicKey'));
            privateKey = V1.encodedToBuffer(bali.getStringForKey(document, '$privateKey'));
        }
    } catch (e) {
        throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
    }

    // return the notary key
    return {

        protocol: protocol,
        tag: tag,
        version: version,
        reference: reference,
        publicKey: publicKey,
        privateKey: privateKey,

        toString: function() {
            var source = NOTARY_TEMPLATE;
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%reference/, this.reference);
            source = source.replace(/%publicKey/, V1.bufferToEncoded(this.publicKey, '    '));
            source = source.replace(/%privateKey/, V1.bufferToEncoded(this.privateKey, '    '));
            return source;
        },

        generate: function() {
            this.protocol = V1.PROTOCOL;
            this.version = 'v1';
            var curve = crypto.createECDH(V1.CURVE);
            curve.generateKeys();
            this.privateKey = curve.getPrivateKey();
            this.publicKey = curve.getPublicKey();
            // sign with new key
            var certificate = this.certify(this.tag, this.version, this.publicKey);
            this.reference = V1.cite(this.tag, this.version, certificate);
            var keyFile = config + this.tag + '.bali';
            try {
                fs.writeFileSync(keyFile, this.toString(), {mode: 384});  // -rw------- permissions
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }
            return certificate;
        },

        regenerate: function() {
            var nextVersion = 'v' + (Number(this.version.slice(1)) + 1);
            var curve = crypto.createECDH(V1.CURVE);
            curve.generateKeys();
            var newPublicKey = curve.getPublicKey();
            // sign with old key
            var certificate = this.certify(this.tag, nextVersion, newPublicKey);
            // sign with new key
            this.version = nextVersion;
            this.privateKey = curve.getPrivateKey();
            this.publicKey = curve.getPublicKey();
            certificate += V1.cite(this.tag, nextVersion, certificate);
            certificate += ' ' + this.sign(certificate) + '\n';
            this.reference = V1.cite(this.tag, nextVersion, certificate);
            var keyFile = config + this.tag + '.bali';
            try {
                fs.writeFileSync(keyFile, this.toString(), {mode: 384});  // -rw------- permissions
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }
            return certificate;
        },

        forget: function() {
            this.privateKey = undefined;
            var keyFile = config + this.tag + '.bali';
            fs.unlinkFileSync(keyFile, this.toString(), {mode: 384});  // -rw------- permissions
            try {
                if (fs.existsSync(keyFile)) {
                    fs.unlinkSync(keyFile);
                }
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }
        },

        sign: function(document) {
            var curve = crypto.createECDH(V1.CURVE);
            curve.setPrivateKey(this.privateKey);
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
            certificate = certificate.replace(/%publicKey/, V1.bufferToEncoded(publicKey, '    '));
            certificate += V1.cite(tag, version);  // no document, self-signed
            certificate += ' ' + this.sign(certificate) + '\n';
            return certificate;
        },

        decrypt: function(aem) {
            // decrypt the 32-byte symmetric key
            var seed = aem.seed;
            var curve = crypto.createECDH(V1.CURVE);
            curve.setPrivateKey(this.privateKey);
            var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

            // decrypt the ciphertext using the symmetric key
            var decipher = crypto.createDecipheriv(V1.CIPHER, symmetricKey, aem.iv);
            decipher.setAuthTag(aem.auth);
            var plaintext = decipher.update(aem.ciphertext, undefined, 'utf8');
            plaintext += decipher.final('utf8');
            return plaintext;
        }
    };
};
