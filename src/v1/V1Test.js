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
var bali = require('bali-component-framework');
var V1Public = require('./V1Public');
var Document = require('../Document').Document;


/**
 * This function returns an object that implements the API for the software security module
 * (notary key) associated with the specified unique tag. The internal attributes for the
 * notary key are hidden from the code that is using the notary key.
 * 
 * @param {Tag} tag The unique tag for the software security module.
 * @param {String} testDirectory An optional directory to use for local testing.
 * @returns {Object} A proxy to the software security module managing the private key.
 */
exports.api = function(tag, testDirectory) {
    
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
        if (fs.existsSync(keyFilename)) {
            // read in the notary key information
            var keySource = fs.readFileSync(keyFilename, 'utf8');
            var catalog = bali.parser.parseComponent(keySource);
            var protocol = catalog.getValue('$protocol');
            if (V1Public.PROTOCOL !== protocol.toString()) {
                throw new Error('NOTARY: The protocol for the test private key is not supported: ' + protocol);
            }
            if (!tag.isEqualTo(catalog.getValue('$tag'))) {
                throw new Error('NOTARY: The tag for the test private key is incorrect: ' + tag);
            }
            currentVersion = catalog.getValue('$version');
            publicKey = catalog.getValue('$publicKey').getBuffer();
            privateKey = catalog.getValue('$privateKey').getBuffer();
            certificateCitation = catalog.getValue('$citation');
        }

        // check for an existing notary certificate file
        if (fs.existsSync(certificateFilename)) {
            // read in the notary certificate information
            var certificateSource = fs.readFileSync(certificateFilename, 'utf8');
            notaryCertificate = Document.fromString(certificateSource);
        }
    } catch (e) {
        throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
    }

    // return the notary key
    return {

        /**
         * This method returns the canonical Bali source code representation for the private
         * notary key.
         * 
         * @returns {String} A canonical Bali source code string for the private notary key.
         */
        toString: function() {
            var catalog = new bali.Catalog();
            catalog.setValue('$protocol', new bali.Version(V1Public.PROTOCOL));
            catalog.setValue('$tag', tag);
            catalog.setValue('$version', currentVersion);
            catalog.setValue('$publicKey', new bali.Binary(publicKey));
            catalog.setValue('$privateKey', new bali.Binary(privateKey));
            catalog.setValue('$citation', certificateCitation);
            return catalog.toString();
        },

        /**
         * This method returns the notary certificate associated with this notary key.
         * 
         * @returns {Document} The notary certificate associated with this notary key.
         */
        certificate: function() {
            return notaryCertificate;
        },

        /**
         * This method returns a citation referencing the notary certificate associated
         * with this notary key.
         * 
         * @returns {Catalog} A citation referencing the notary certificate associated
         * with this notary key.
         */
        citation: function() {
            return certificateCitation;
        },

        /**
         * This method generates a new public-private key pair and uses the private key as the
         * new notary key. It returns the new public notary certificate.
         * 
         * NOTE: Ideally, it would make more sense for most of this method to be moved to the
         * <code>BaliNotary</code> class but can't be moved there because during regeneration
         * both the old key and new key must sign the new certificate and the old key goes
         * away right after it signs it. So the complete certificate signing process must
         * happen in the security model.
         * 
         * @returns {Document} The new notary certificate.
         */
        generate: function() {
            var isRegeneration = !!privateKey;

            // generate a new public-private key pair
            var curve = crypto.createECDH(V1Public.CURVE);
            curve.generateKeys();
            currentVersion = currentVersion ? 'v' + (Number(currentVersion.toString().slice(1)) + 1) : 'v1';
            currentVersion = new bali.Version(currentVersion);
            publicKey = curve.getPublicKey();

            // generate the new public notary certificate
            notaryCertificate = new bali.Catalog();
            notaryCertificate.setValue('$protocol', new bali.Version(V1Public.PROTOCOL));
            notaryCertificate.setValue('$tag', tag);
            notaryCertificate.setValue('$version', currentVersion);
            notaryCertificate.setValue('$publicKey', new bali.Binary(publicKey));

            var certificateSource = notaryCertificate.toString();
            if (isRegeneration) {
                var previousReference = V1Public.referenceFromCitation(certificateCitation).toString();
                // append a reference to the previous version of the certificate
                certificateSource += Document.DIVIDER + previousReference;

                // append a reference to the certificate for the old private key
                certificateSource += Document.DIVIDER + previousReference;

                // sign the certificate with the old private key
                certificateSource += '\n' + this.sign(certificateSource);
            } else {
                // append a reference to the previous version of the certificate (none)
                certificateSource += Document.DIVIDER + bali.Template.NONE;
            }

            // create a reference to the certificate for the new private key
            privateKey = curve.getPrivateKey();
            var newCitation = V1Public.citationFromAttributes(tag, currentVersion);  // no digest since it is self-referential
            var newReference = V1Public.referenceFromCitation(newCitation).toString();

            // append a reference to the certificate for the new private key
            certificateSource += Document.DIVIDER + newReference;

            // sign the certificate with the new private key
            certificateSource += '\n' + this.sign(certificateSource) + '\n';  // POSIX compliance

            // generate a citation for the new certificate
            certificateCitation = V1Public.cite(tag, currentVersion, certificateSource);

            // save the state of this notary key and certificate in the local configuration
            try {
                var keySource = this.toString() + '\n';  // POSIX compliance
                fs.writeFileSync(keyFilename, keySource, {encoding: 'utf8', mode: 384});  // -rw------- permissions
                fs.writeFileSync(certificateFilename, certificateSource, {encoding: 'utf8', mode: 384});  // -rw------- permissions
            } catch (e) {
                throw new Error('NOTARY: The TEST filesystem is not currently accessible:\n' + e);
            }

            notaryCertificate = Document.fromString(certificateSource);
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
         * This method generates a digital signature of the specified message using the notary
         * key. The resulting digital signature is base 32 encoded and may be verified using the
         * V1Public.verify() method and the corresponding public key.
         * 
         * @param {String} message The message to be digitally signed.
         * @returns {Binary} A base 32 encoded digital signature of the message.
         */
        sign: function(message) {
            var curve = crypto.createECDH(V1Public.CURVE);
            curve.setPrivateKey(privateKey);
            var pem = ec_pem(curve, V1Public.CURVE);
            var signer = crypto.createSign(V1Public.SIGNATURE);
            signer.update(message);
            var signature = signer.sign(pem.encodePrivateKey());
            var binary = new bali.Binary(signature);
            return binary;
        },

        /**
         * This function uses the notary key to decrypt the specified authenticated encrypted
         * message. The result is the decrypted message.
         * 
         * @param {Catalog} aem The authenticated encrypted message to be decrypted.
         * @returns {String} The decrypted plaintext message.
         */
        decrypt: function(aem) {
            var protocol = aem.getValue('$protocol');
            if (V1Public.PROTOCOL !== protocol.toString()) {
                throw new Error('NOTARY: The protocol for decrypting a message is not supported: ' + protocol);
            }
            var iv = aem.getValue('$iv').getBuffer();
            var auth = aem.getValue('$auth').getBuffer();
            var seed = aem.getValue('$seed').getBuffer();
            var ciphertext = aem.getValue('$ciphertext').getBuffer();

            // decrypt the 32-byte symmetric key
            var curve = crypto.createECDH(V1Public.CURVE);
            curve.setPrivateKey(privateKey);
            var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

            // decrypt the ciphertext using the symmetric key
            var decipher = crypto.createDecipheriv(V1Public.CIPHER, symmetricKey, iv);
            decipher.setAuthTag(auth);
            var message = decipher.update(ciphertext, undefined, 'utf8');
            message += decipher.final('utf8');
            return message;
        }
    };
};
