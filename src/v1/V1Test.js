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
var fs = require('fs');
var config = require('os').homedir() + '/.bali/';
var crypto = require('crypto');
var ec_pem = require('ec-pem');
var bali = require('bali-document-notation');
var V1 = require('./V1');


/**
 * This function returns an object that implements the API for the software security module
 * (notary key) associated with the specified unique tag. The internal attributes for the
 * notary key are hidden from the code that is using the notary key.
 * 
 * @param {String} tag The unique tag for the software security module.
 * @param {String} testDirectory An optional directory to use for local testing.
 * @returns {Object} A proxy to the software security module managing the private key.
 */
exports.notaryKey = function(tag, testDirectory) {
    
    // read in the notary key attributes
    var currentVersion;     // the version of the notary key
    var publicKey;   // the public key residing in the certificate in the cloud
    var privateKey;  // the private key that is used for signing and decryption
    var notaryCertificate; // the public notary certificate containing the public key
    var certificateCitation;    // a reference citation to the public notary certificate
    if (testDirectory) config = testDirectory;
    var keyFilename = config + 'NotaryKey.bali';
    var certificateFilename = config + 'NotaryCertificate.bali';
    try {
        // create the configuration directory if necessary
        if (!fs.existsSync(config)) fs.mkdirSync(config, 448);  // drwx------ permissions

        // check for an existing notary key file
        var source;
        if (fs.existsSync(keyFilename)) {
            // read in the notary key information
            source = fs.readFileSync(keyFilename).toString();
            var document = bali.parser.parseDocument(source);
            var protocol = document.getString('$protocol');
            if (V1.PROTOCOL !== protocol) {
                throw new Error('NOTARY: The protocol for the test private key is not supported: ' + protocol);
            }
            if (tag !== document.getString('$tag')) {
                throw new Error('NOTARY: The tag for the test private key is incorrect: ' + tag);
            }
            currentVersion = document.getString('$version');
            certificateCitation = V1.Citation.fromReference(document.getString('$citation'));
            publicKey = V1.encodedToBuffer(document.getString('$publicKey'));
            privateKey = V1.encodedToBuffer(document.getString('$privateKey'));
        }

        // check for an existing notary certificate file
        if (fs.existsSync(certificateFilename)) {
            // read in the notary certificate information
            source = fs.readFileSync(certificateFilename).toString();
            notaryCertificate = bali.parser.parseDocument(source);
        }
    } catch (e) {
        throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
    }

    // return the notary key
    return {
        /**
         * This method implements the standard toString() method for the notary key by
         * delegating to the toSource() method which produces a canonical Bali source
         * code string for the notary key.
         * 
         * @returns {String} A canonical Bali source code string for the notary key.
         */
        toString: function() {
            var string = this.toSource();
            return string;
        },

        /**
         * This method returns the canonical Bali source code representation for the notary
         * key. It allows an optional indentation to be included which will be prepended
         * to each indented line of the resulting string.
         * 
         * @param {String} indentation A string of spaces to be used as additional indentation
         * for each line within the resulting string.
         * @returns {String} A canonical Bali source code string for the notary key.
         */
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
            source = source.replace(/%protocol/, V1.PROTOCOL);
            source = source.replace(/%tag/, tag);
            source = source.replace(/%version/, currentVersion);
            source = source.replace(/%citation/, certificateCitation.toReference());
            source = source.replace(/%publicKey/, V1.bufferToEncoded(publicKey, indentation + '    '));
            source = source.replace(/%privateKey/, V1.bufferToEncoded(privateKey, indentation + '    '));
            return source;
        },

        /**
         * This method returns the notary certificate associated with this notary key.
         * 
         * @returns {String} The notary certificate associated with this notary key.
         */
        certificate: function() {
            return notaryCertificate;
        },

        /**
         * This method returns a citation referencing the notary certificate associated
         * with this notary key.
         * 
         * @returns {Citation} A citation referencing the notary certificate associated
         * with this notary key.
         */
        citation: function() {
            return certificateCitation;
        },

        /**
         * This method generates a new public-private key pair and uses the private key as the
         * new notary key. It returns the Bali source code for the public notary certificate as
         * well as a reference citation to the new certificate.
         * 
         * @returns {Object} An object containing the Bali source code for the new notary
         * certificate and a reference citation to the certificate's location in the Bali
         * Cloud Environment™.
         */
        generate: function() {
            var isRegeneration = !!privateKey;

            // generate a new public-private key pair
            var curve = crypto.createECDH(V1.CURVE);
            curve.generateKeys();
            currentVersion = currentVersion ? 'v' + (Number(currentVersion.slice(1)) + 1) : 'v1';
            publicKey = curve.getPublicKey();

            // generate the new public notary certificate
            var source = 
                '[\n' +
                '    $protocol: %protocol\n' +
                '    $tag: %tag\n' +
                '    $version: %version\n' +
                '    $publicKey: %publicKey\n' +
                ']';
            source = source.replace(/%protocol/, V1.PROTOCOL);
            source = source.replace(/%tag/, tag);
            source = source.replace(/%version/, currentVersion);
            source = source.replace(/%publicKey/, V1.bufferToEncoded(publicKey, '    '));

            if (isRegeneration) {
                // sign the certificate with the old private key
                var previousReference = certificateCitation.toReference();
                source = previousReference + '\n' + source + '\n' + previousReference;
                source += ' ' + this.sign(source);
            }

            // sign the certificate with the new private key
            privateKey = curve.getPrivateKey();
            source += '\n' + V1.cite(tag, currentVersion);  // no source since it is self-signed
            source += ' ' + this.sign(source) + '\n';

            // generate a citation for the new certificate
            notaryCertificate = bali.parser.parseDocument(source);
            certificateCitation = V1.Citation.fromReference(V1.cite(tag, currentVersion, source));

            // save the state of this notary key and certificate in the local configuration
            try {
                fs.writeFileSync(keyFilename, this.toSource(), {mode: 384});  // -rw------- permissions
                fs.writeFileSync(certificateFilename, source, {mode: 384});  // -rw------- permissions
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }

            return notaryCertificate;
        },

        /**
         * This method causes the notary key to forget all information it knows about the
         * current public-private key pair.
         */
        forget: function() {
            currentVersion = undefined;
            certificateCitation = undefined;
            publicKey = undefined;
            privateKey = undefined;
            try {
                if (fs.existsSync(keyFilename)) {
                    // remove the configuration file
                    fs.unlinkSync(keyFilename);
                }
                if (fs.existsSync(certificateFilename)) {
                    // remove the configuration file
                    fs.unlinkSync(certificateFilename);
                }
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }
        },

        /**
         * This method generates a digital signature of the specified document using the notary
         * key. The resulting digital signature is base 32 encoded and may be verified using the
         * V1Public.verify() method and the corresponding public key.
         * 
         * @param {String} document The document to be digitally signed.
         * @returns {String} A base 32 encoded digital signature of the document.
         */
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

        /**
         * This function uses the notary key to encrypt the specified authenticated encrypted
         * message. The result is the decrypted message.
         * 
         * @param {Object} aem The authenticated encrypted message to be decrypted.
         * @returns {String} The decrypted plaintext message.
         */
        decrypt: function(aem) {
            // decrypt the 32-byte symmetric key
            var seed = aem.seed;
            var curve = crypto.createECDH(V1.CURVE);
            curve.setPrivateKey(privateKey);
            var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

            // decrypt the ciphertext using the symmetric key
            var decipher = crypto.createDecipheriv(V1.CIPHER, symmetricKey, aem.iv);
            decipher.setAuthTag(aem.auth);
            var message = decipher.update(aem.ciphertext, undefined, 'utf8');
            message += decipher.final('utf8');
            return message;
        }
    };
};
