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
const Public = require('./Public');

// This private constant sets the POSIX end of line character
const EOL = '\n';


/**
 * This function returns an object that implements the API for the test software security module
 * (containing the notary key). The internal attributes for the notary key are hidden from the
 * code that is using the notary key, but it is NOT fool-proof.
 * 
 * @param {Tag} account The unique tag for the account that owns the notary key.
 * @param {String} testDirectory An optional directory to use for local testing.
 * @returns {Object} A proxy to the test software security module managing the private key.
 */
exports.api = function(account, testDirectory) {

    // analyze the parameters
    if (!account || account.getTypeId() !== bali.types.TAG) {
        throw bali.exception({
            $module: '$Test',
            $procedure: '$api',
            $exception: '$invalidParameter',
            $parameter: account,
            $message: '"The specified account tag is invalid."'
        });
    }

    // create the configuration directory structure if necessary (with drwx------ permissions)
    var configDirectory = testDirectory || os.homedir() + '/.bali/';
    if (!fs.existsSync(configDirectory)) fs.mkdirSync(configDirectory, 448);
    configDirectory += account + '/';
    if (!fs.existsSync(configDirectory)) fs.mkdirSync(configDirectory, 448);
    const keyFilename = configDirectory + 'NotaryKey.bali';
    const certificateFilename = configDirectory + 'NotaryCertificate.ndoc';
    
    // read in the notary key attributes
    var notaryTag;            // the unique tag for the notary key
    var version;              // the current version of the notary key
    var timestamp;            // the timestamp of when the key was generated
    var publicKey;            // the public key residing in the certificate in the cloud
    var privateKey;           // the local private key that is used for signing and decryption
    var notaryCertificate;    // the public notary certificate containing the public key
    var certificateCitation;  // a document citation for the public notary certificate
    try {

        // check for an existing notary key file
        if (fs.existsSync(keyFilename)) {

            // read in the notary key information
            const keySource = fs.readFileSync(keyFilename, 'utf8');
            const keys = bali.parse(keySource);
            const parameters = keys.getParameters();
            notaryTag = parameters.getParameter('$tag');
            version = parameters.getParameter('$version');
            timestamp = keys.getValue('$timestamp').getValue();
            publicKey = keys.getValue('$publicKey').getValue();
            privateKey = keys.getValue('$privateKey').getValue();
            certificateCitation = keys.getValue('$citation');
        }

        // check for an existing notary certificate file
        if (fs.existsSync(certificateFilename)) {
            // read in the notary certificate information
            const certificateSource = fs.readFileSync(certificateFilename, 'utf8');
            notaryCertificate = bali.parse(certificateSource);
        }

    } catch (e) {
        throw bali.exception({
            $module: '$Test',
            $procedure: '$api',
            $exception: '$directoryAccess',
            $directory: '"' + configDirectory + '"',
            $message: '"The configuration directory could not be accessed."'
        });
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
            const catalog = bali.catalog({
                $protocol: Public.protocol,
                $timestamp: timestamp,
                $account: account,
                $publicKey: bali.binary(publicKey),
                $privateKey: bali.binary(privateKey),
                $citation: certificateCitation
            }, bali.parameters({
                $tag: notaryTag,
                $version: version
            }));
            return catalog.toString();
        },

        /**
         * This method returns the notary certificate associated with this notary key.
         * 
         * @returns {Catalog} The notary certificate associated with this notary key.
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
         * <code>DigitalNotary</code> class but it can't be moved there because during regeneration
         * the old key key must sign the new certificate and the old key goes away right after the
         * new one is generated.
         * 
         * @returns {Catalog} The new notary certificate.
         */
        generate: function() {
            const isRegeneration = !!privateKey;

            // generate a new public-private key pair
            const curve = crypto.createECDH(Public.CURVE);
            curve.generateKeys();
            notaryTag = notaryTag || bali.tag();  // generate a new tag if necessary
            version = version ? bali.version.nextVersion(version) : bali.version();
            timestamp = bali.moment();
            publicKey = curve.getPublicKey();

            // generate the new notary certificate
            const component = bali.catalog({
                $protocol: Public.protocol,
                $timestamp: timestamp,
                $account: account,
                $publicKey: bali.binary(publicKey)
            }, bali.parameters({
                $tag: notaryTag,
                $version: version
            }));

            // assemble and sign the notary certificate source
            var previous, citation;
            if (isRegeneration) {
                // sign with the old key
                citation = certificateCitation;  // signed with old certificate
                previous = certificateCitation;  // previous version is old certificate
            } else {
                // self sign with the new key
                privateKey = curve.getPrivateKey();  // sign with new key
            }

            // create the new notary certificate
            notaryCertificate = bali.catalog({});
            notaryCertificate.setValue('$protocol', Public.protocol);
            notaryCertificate.setValue('$timestamp', bali.moment());  // now
            if (previous) notaryCertificate.setValue('$previous', previous);
            notaryCertificate.setValue('$component', component);
            if (citation) notaryCertificate.setValue('$citation', citation);
            notaryCertificate.setValue('$signature', this.sign(notaryCertificate));

            // save the new key
            privateKey = curve.getPrivateKey();

            // cache the new certificate citation
            const digest = Public.digest(notaryCertificate);
            certificateCitation = Public.citation(notaryTag, version, digest);

            // save the state of this notary key and certificate in the local configuration
            try {
                const keySource = this.toString() + EOL;  // add POSIX compliant <EOL>
                const certificateSource = notaryCertificate.toString() + EOL;  // add POSIX compliant <EOL>
                fs.writeFileSync(keyFilename, keySource, {encoding: 'utf8', mode: 384});  // -rw------- permissions
                fs.writeFileSync(certificateFilename, certificateSource, {encoding: 'utf8', mode: 384});  // -rw------- permissions
            } catch (e) {
                throw bali.exception({
                    $module: '$Test',
                    $procedure: '$generate',
                    $exception: '$directoryAccess',
                    $directory: '"' + configDirectory + '"',
                    $message: '"The configuration directory could not be accessed."'
                });
            }

            return notaryCertificate;
        },

        /**
         * This method causes the notary key to forget all information it knows about the
         * current public-private key pair.
         */
        forget: function() {
            version = undefined;
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
                throw bali.exception({
                    $module: '$Test',
                    $procedure: '$forget',
                    $exception: '$directoryAccess',
                    $directory: '"' + configDirectory + '"',
                    $message: '"The configuration directory could not be accessed."'
                });
            }
        },

        /**
         * This method generates a digital signature of the specified message using the local
         * notary key. The resulting digital signature is base 32 encoded and may be verified
         * using the Public.verify() method and the corresponding public key.
         * 
         * @param {String} message The message to be digitally signed.
         * @returns {Binary} A base 32 encoded digital signature of the message.
         */
        sign: function(message) {
            const curve = crypto.createECDH(Public.CURVE);
            curve.setPrivateKey(privateKey);
            const pem = ec_pem(curve, Public.CURVE);
            const signer = crypto.createSign(Public.SIGNATURE);
            signer.update(message.toString());  // force it to a string if it isn't already
            const signature = signer.sign(pem.encodePrivateKey());
            const binary = bali.binary(signature);
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
            const seed = aem.getValue('$seed').getValue();
            const iv = aem.getValue('$iv').getValue();
            const auth = aem.getValue('$auth').getValue();
            const ciphertext = aem.getValue('$ciphertext').getValue();

            // decrypt the 32-byte symmetric key
            const curve = crypto.createECDH(Public.CURVE);
            curve.setPrivateKey(privateKey);
            const symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

            // decrypt the ciphertext using the symmetric key
            const decipher = crypto.createDecipheriv(Public.CIPHER, symmetricKey, iv);
            decipher.setAuthTag(auth);
            var message = decipher.update(ciphertext, undefined, 'utf8');
            message += decipher.final('utf8');
            return message;
        }
    };
};
