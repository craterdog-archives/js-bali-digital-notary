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

///////////////////////////////////////////////////////////////////////////////////////
// This module should be used for LOCAL TESTING ONLY.  It is NOT SECURE and provides //
// no guarantees on protecting access to the private key.  YOU HAVE BEEN WARNED!!!   //
///////////////////////////////////////////////////////////////////////////////////////


/*
 * This module uses the singleton pattern to provide an object that simulates a hardware
 * security module (HSM) for all cryptographic operations involving the private key. It
 * implements these operations as a software security module to allow testing without an
 * actual HSM.
 */
var V1 = require('./V1');
var BaliDocument = require('bali-document-notation/BaliDocument');
var crypto = require('crypto');
var ec_pem = require('ec-pem');
var config = require('os').homedir() + '/.bali/';
var fs = require('fs');


/**
 * This function returns an object that implements the API for the software security module
 * (notary key) associated with the specified unique tag.
 * 
 * @param {String} tag The unique tag for the software security module.
 * @param {String} testDirectory An optional directory to use for local testing.
 * @returns {Object} A proxy to the software security module managing the private key.
 */
exports.notaryKey = function(tag, testDirectory) {
    
    // read in the notary key attributes
    var protocol;
    var version;
    var citation;
    var publicKey;
    var privateKey;
    if (testDirectory) config = testDirectory;
    var filename = config + tag + '.bali';
    try {
        // create the configuration directory if necessary
        if (!fs.existsSync(config)) fs.mkdirSync(config, 448);  // drwx------ permissions

        // check for an existing configuration file
        if (fs.existsSync(filename)) {
            // read in the notary key information
            var source = fs.readFileSync(filename).toString();
            var document = BaliDocument.fromSource(source);
            protocol = document.getString('$protocol');
            if (V1.PROTOCOL !== protocol) {
                throw new Error('NOTARY: The protocol for the test private key is not supported: ' + protocol);
            }
            version = document.getString('$version');
            citation = document.getString('$citation');
            publicKey = V1.encodedToBuffer(document.getString('$publicKey'));
            privateKey = V1.encodedToBuffer(document.getString('$privateKey'));
        }
    } catch (e) {
        throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
    }

    // return the notary key
    return {

        toString: function() {
            var string = this.toSource();
            return string;
        },

        toSource: function(indentation) {
            indentation = indentation ? indentation : '';
            var source =  '[\n' +
                indentation + '    $protocol: %protocol\n' +
                indentation + '    $tag: %tag\n' +
                indentation + '    $version: %version\n' +
                indentation + '    $citation: %citation\n' +
                indentation + '    $publicKey: %publicKey\n' +
                indentation + '    $privateKey: %privateKey\n' +
                indentation + ']\n';
            source = source.replace(/%protocol/, protocol);
            source = source.replace(/%tag/, tag);
            source = source.replace(/%version/, version);
            source = source.replace(/%citation/, citation);
            source = source.replace(/%publicKey/, V1.bufferToEncoded(publicKey, indentation + '    '));
            source = source.replace(/%privateKey/, V1.bufferToEncoded(privateKey, indentation + '    '));
            return source;
        },

        generate: function() {
            protocol = V1.PROTOCOL;
            version = 'v1';
            var curve = crypto.createECDH(V1.CURVE);
            curve.generateKeys();
            privateKey = curve.getPrivateKey();
            publicKey = curve.getPublicKey();
            // sign with new key
            var source = certify(this, tag, version, publicKey);
            citation = V1.cite(tag, version, source);
            try {
                fs.writeFileSync(filename, this.toSource(), {mode: 384});  // -rw------- permissions
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }
            return {
                citation: citation,
                source: source
            };
        },

        regenerate: function() {
            var nextVersion = 'v' + (Number(version.slice(1)) + 1);
            var curve = crypto.createECDH(V1.CURVE);
            curve.generateKeys();
            var newPublicKey = curve.getPublicKey();
            // sign with old key
            var source = certify(this, tag, nextVersion, newPublicKey);
            // sign with new key
            version = nextVersion;
            privateKey = curve.getPrivateKey();
            publicKey = curve.getPublicKey();
            source += V1.cite(tag, nextVersion, source);
            source += ' ' + this.sign(source) + '\n';
            citation = V1.cite(tag, nextVersion, source);
            try {
                fs.writeFileSync(filename, this.toSource(), {mode: 384});  // -rw------- permissions
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }
            return {
                citation: citation,
                source: source
            };
        },

        forget: function() {
            version = undefined;
            citation = undefined;
            publicKey = undefined;
            privateKey = undefined;
            try {
                if (fs.existsSync(filename)) {
                    fs.unlinkSync(filename);
                }
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }
        },

        citation: function() {
            return citation;
        },

        sign: function(document) {
            var curve = crypto.createECDH(V1.CURVE);
            curve.setPrivateKey(privateKey);
            var pem = ec_pem(curve, V1.CURVE);
            var signer = crypto.createSign(V1.SIGNATURE);
            signer.update(document);
            var signature = signer.sign(pem.encodePrivateKey());
            var encodedSignature = V1.bufferToEncoded(signature);
            return encodedSignature;
        },

        decrypt: function(aem) {
            // decrypt the 32-byte symmetric key
            var seed = aem.seed;
            var curve = crypto.createECDH(V1.CURVE);
            curve.setPrivateKey(privateKey);
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


// PRIVATE FUNCTIONS

function certify(notaryKey, tag, version, publicKey) {
    var source = 
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $publicKey: %publicKey\n' +
        ']\n';

    source = source.replace(/%protocol/, V1.PROTOCOL);
    source = source.replace(/%tag/, tag);
    source = source.replace(/%version/, version);
    source = source.replace(/%publicKey/, V1.bufferToEncoded(publicKey, '    '));
    source += V1.cite(tag, version);  // no document, self-signed
    source += ' ' + notaryKey.sign(source) + '\n';
    return source;
}
