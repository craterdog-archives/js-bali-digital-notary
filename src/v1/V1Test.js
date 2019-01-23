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
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const ec_pem = require('ec-pem');
const bali = require('bali-component-framework');
const NotarizedDocument = require('../NotarizedDocument').NotarizedDocument;
const v1Public = require('./V1Public');


/**
 * This function returns an object that implements the API for the software security module
 * (notary key) associated with the specified unique tag. The internal attributes for the
 * notary key are hidden from the code that is using the notary key, but it is NOT fool-proof.
 * 
 * @param {Tag} tag The unique tag for the software security module.
 * @param {String} testDirectory An optional directory to use for local testing.
 * @returns {Object} A proxy to the test software security module managing the private key.
 */
exports.api = function(tag, testDirectory) {

    // create the config directory if necessary
    const configDirectory = testDirectory || os.homedir() + '/.bali/';
    if (!fs.existsSync(configDirectory)) fs.mkdirSync(configDirectory, 448);  // drwx------ permissions
    const keyFilename = configDirectory + 'NotaryKey.bali';
    const certificateFilename = configDirectory + 'NotaryCertificate.bdoc';
    
    // read in the notary key attributes
    var currentVersion;        // the current version of the notary key
    var publicKey;             // the public key residing in the certificate in the cloud
    var privateKey;            // the local private key that is used for signing and decryption
    var notaryCertificate;     // the public notary certificate containing the public key
    var certificateCitation;   // a document citation for the public notary certificate
    try {

        // check for an existing notary key file
        if (fs.existsSync(keyFilename)) {

            // read in the notary key information
            const keySource = fs.readFileSync(keyFilename, 'utf8');
            const catalog = bali.parse(keySource);
            const protocol = catalog.getValue('$protocol');
            if (v1Public.PROTOCOL !== protocol.toString()) {
                const attributes = bali.Catalog.fromSequential({
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: 'The protocol for the notary key is not supported.'
                });
                throw new bali.Exception(attributes);
            }
            if (!tag.isEqualTo(catalog.getValue('$tag'))) {
                const attributes = bali.Catalog.fromSequential({
                    $exception: '$invalidKey',
                    $tag: tag,
                    $message: 'The notary key is invalid.'
                });
                throw new bali.Exception(attributes);
            }
            currentVersion = catalog.getValue('$version');
            publicKey = catalog.getValue('$publicKey').value;
            privateKey = catalog.getValue('$privateKey').value;
            certificateCitation = catalog.getValue('$citation');
        }

        // check for an existing notary certificate file
        if (fs.existsSync(certificateFilename)) {
            // read in the notary certificate information
            const certificateSource = fs.readFileSync(certificateFilename, 'utf8');
            notaryCertificate = NotarizedDocument.fromString(certificateSource);
        }

    } catch (e) {
        const attributes = bali.Catalog.fromSequential({
            $exception: '$directoryAccess',
            $directory: configDirectory,
            $message: 'The configuration directory could not be accessed.'
        });
        throw new bali.Exception(attributes);
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
            const catalog = new bali.Catalog();
            catalog.setValue('$protocol', bali.Version.fromLiteral(v1Public.PROTOCOL));
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
         * @returns {NotarizedDocument} The notary certificate associated with this notary key.
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
         * <code>DigitalNotary</code> class but can't be moved there because during regeneration
         * both the old key and new key must sign the new certificate and the old key goes
         * away right after it signs it. So the complete certificate signing process must
         * happen in the security model.
         * 
         * @returns {NotarizedDocument} The new notary certificate.
         */
        generate: function() {
            const isRegeneration = !!privateKey;

            // generate a new public-private key pair
            const curve = crypto.createECDH(v1Public.CURVE);
            curve.generateKeys();
            currentVersion = currentVersion ? 'v' + (Number(currentVersion.toString().slice(1)) + 1) : 'v1';
            currentVersion = bali.Version.fromLiteral(currentVersion);
            publicKey = curve.getPublicKey();

            // generate the new public notary certificate
            notaryCertificate = new bali.Catalog();
            notaryCertificate.setValue('$protocol', bali.Version.fromLiteral(v1Public.PROTOCOL));
            notaryCertificate.setValue('$tag', tag);
            notaryCertificate.setValue('$version', currentVersion);
            notaryCertificate.setValue('$publicKey', new bali.Binary(publicKey));

            // create a reference to the certificate for the new private key
            privateKey = curve.getPrivateKey();
            const newCitation = v1Public.citationFromAttributes(tag, currentVersion);  // no digest since it is self-referential
            const newReference = v1Public.referenceFromCitation(newCitation);

            var certificateSource = '';
            if (isRegeneration) {
                // sign with the old key
                var certificateReference = v1Public.referenceFromCitation(certificateCitation);
                certificateSource += certificateReference + '\n';
                certificateSource += certificateReference + '\n';  // previous version is the old certificate
                certificateSource += notaryCertificate;
                certificateSource = this.sign(certificateSource) + '\n' + certificateSource;
            } else {
                // sign with the new key
                certificateSource += newReference + '\n';
                certificateSource += bali.Pattern.fromLiteral('none') + '\n';  // there is no previous version
                certificateSource += notaryCertificate;
                certificateSource = this.sign(certificateSource) + '\n' + certificateSource;
            }

            // cache the new notary certificate
            notaryCertificate = NotarizedDocument.fromString(certificateSource);

            // cache the new certificate citation
            certificateCitation = v1Public.cite(tag, currentVersion, certificateSource);

            // save the state of this notary key and certificate in the local configuration
            try {
                const keySource = this.toString() + '\n';  // add POSIX compliant <EOL>
                certificateSource += '\n';  // add POSIX compliant <EOL>
                fs.writeFileSync(keyFilename, keySource, {encoding: 'utf8', mode: 384});  // -rw------- permissions
                fs.writeFileSync(certificateFilename, certificateSource, {encoding: 'utf8', mode: 384});  // -rw------- permissions
            } catch (e) {
                const attributes = bali.Catalog.fromSequential({
                    $exception: '$directoryAccess',
                    $directory: configDirectory,
                    $message: 'The configuration directory could not be accessed.'
                });
                throw new bali.Exception(attributes);
            }

            return notaryCertificate;
        },

        /**
         * This method causes the notary key to forget all information it knows about the
         * current public-private key pair.
         */
        forget: function() {
            currentVersion = undefined;
            publicKey = undefined;
            privateKey = undefined;
            certificateCitation = undefined;
            notaryCertificate = undefined;
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
                const attributes = bali.Catalog.fromSequential({
                    $exception: '$directoryAccess',
                    $directory: configDirectory,
                    $message: 'The configuration directory could not be accessed.'
                });
                throw new bali.Exception(attributes);
            }
        },

        /**
         * This method generates a digital signature of the specified message using the local
         * notary key. The resulting digital signature is base 32 encoded and may be verified
         * using the v1Public.verify() method and the corresponding public key.
         * 
         * @param {String} message The message to be digitally signed.
         * @returns {Binary} A base 32 encoded digital signature of the message.
         */
        sign: function(message) {
            const curve = crypto.createECDH(v1Public.CURVE);
            curve.setPrivateKey(privateKey);
            const pem = ec_pem(curve, v1Public.CURVE);
            const signer = crypto.createSign(v1Public.SIGNATURE);
            signer.update(message);
            const signature = signer.sign(pem.encodePrivateKey());
            const binary = new bali.Binary(signature);
            return binary;
        },

        /**
         * This function uses the local notary key to decrypt the specified authenticated
         * encrypted message (AEM). The result is the decrypted plaintext message.
         * 
         * @param {Catalog} aem The authenticated encrypted message to be decrypted.
         * @returns {String} The decrypted plaintext message.
         */
        decrypt: function(aem) {
            const protocol = aem.getValue('$protocol');
            if (v1Public.PROTOCOL !== protocol.toString()) {
                const attributes = bali.Catalog.fromSequential({
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: 'The protocol for the encrypted message is not supported.'
                });
                throw new bali.Exception(attributes);
            }
            const iv = aem.getValue('$iv').value;
            const auth = aem.getValue('$auth').value;
            const seed = aem.getValue('$seed').value;
            const ciphertext = aem.getValue('$ciphertext').value;

            // decrypt the 32-byte symmetric key
            const curve = crypto.createECDH(v1Public.CURVE);
            curve.setPrivateKey(privateKey);
            const symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

            // decrypt the ciphertext using the symmetric key
            const decipher = crypto.createDecipheriv(v1Public.CIPHER, symmetricKey, iv);
            decipher.setAuthTag(auth);
            var message = decipher.update(ciphertext, undefined, 'utf8');
            message += decipher.final('utf8');
            return message;
        }
    };
};
