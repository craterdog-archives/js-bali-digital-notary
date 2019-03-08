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
const pfs = require('fs').promises;
const os = require('os');
const crypto = require('crypto');
const ec_pem = require('ec-pem');
const bali = require('bali-component-framework');
const HSMPublic = require('./HSMPublic');

// This private constant sets the POSIX end of line character
const EOL = '\n';


/**
 * This function returns an object that implements the API for the test software security module
 * (containing the notary key). The internal attributes for the notary key are hidden from the
 * code that is using the notary key, but it is NOT fool-proof.
 * 
 * @param {Tag} account The unique tag for the account that owns the notary key.
 * @param {String} testDirectory An optional directory to use for local testing.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} A proxy to the test software security module managing the private key.
 */
exports.api = function(account, testDirectory, debug) {
    debug = debug || false;

    var notaryTag;            // the unique tag for the notary key
    var version;              // the current version of the notary key
    var timestamp;            // the timestamp of when the key was generated
    var publicKey;            // the public key residing in the certificate in the cloud
    var privateKey;           // the local private key that is used for signing and decryption
    var notaryCertificate;    // the public notary certificate containing the public key
    var certificateCitation;  // a document citation for the public notary certificate
    var configDirectory;      // the path to the configuration directory
    var keyFilename;          // the name of the configuration file containing the keys
    var certificateFilename;  // the name of the configuration file containing the certificate

    return {

        /**
         * This function returns a string providing attributes about this test HSM.
         * 
         * @returns {String} A string providing attributes about this test HSM.
         */
        toString: function() {
            const catalog = bali.catalog({
                $module: '$HSMTest',
                $account: account,
                $citation: certificateCitation
            }, bali.parameters({
                $tag: notaryTag,
                $version: version
            }));
            return catalog.toString();
        },

        /**
         * This function initializes the API.
         */
        initialize: async function() {
            try {
                // create the configuration directory structure if necessary (with drwx------ permissions)
                configDirectory = testDirectory || os.homedir() + '/.bali/';
                await pfs.mkdir(configDirectory, 0o700).catch(function() {});
                configDirectory += account.getValue() + '/';
                await pfs.mkdir(configDirectory, 0o700).catch(function() {});
                keyFilename = configDirectory + 'NotaryKey.bali';
                certificateFilename = configDirectory + 'NotaryCertificate.ndoc';

                // read in the notary key attributes (if possible)
                try {
                    if (await doesExist(keyFilename)) {
                        // read in the notary key information
                        const keySource = await pfs.readFile(keyFilename, 'utf8');
                        const keys = bali.parse(keySource);
                        const parameters = keys.getParameters();
                        notaryTag = parameters.getParameter('$tag');
                        version = parameters.getParameter('$version');
                        timestamp = keys.getValue('$timestamp').getValue();
                        publicKey = keys.getValue('$publicKey').getValue();
                        privateKey = keys.getValue('$privateKey').getValue();
                        certificateCitation = keys.getValue('$citation');
                    }
                    if (await doesExist(certificateFilename)) {
                        // read in the notary certificate information
                        const certificateSource = await pfs.readFile(certificateFilename, 'utf8');
                        notaryCertificate = bali.parse(certificateSource);
                    }
                } catch (cause) {
                    const exception = bali.exception({
                        $module: '$HSMTest',
                        $function: '$initialize',
                        $exception: '$directoryAccess',
                        $account: account || bali.NONE,
                        $directory: configDirectory ? bali.text(configDirectory) : bali.NONE,
                        $text: bali.text('The configuration directory could not be accessed.')
                    }, cause);
                    throw exception;
                }
                this.initialize = function() {
                    const exception = bali.exception({
                        $module: '$HSMTest',
                        $function: '$initialize',
                        $exception: '$alreadyInitialized',
                        $account: account || bali.NONE,
                        $directory: configDirectory ? bali.text(configDirectory) : bali.NONE,
                        $text: bali.text('The test private API has already been initialized.')
                    });
                    throw exception;
                };
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$HSMTest',
                    $function: '$initialize',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $directory: configDirectory ? bali.text(configDirectory) : bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to initialize the API.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function returns the notary certificate associated with this notary key.
         * 
         * @returns {Catalog} The notary certificate associated with this notary key.
         */
        certificate: async function() {
            return notaryCertificate;
        },

        /**
         * This function returns a citation referencing the notary certificate associated
         * with this notary key.
         * 
         * @returns {Catalog} A citation referencing the notary certificate associated
         * with this notary key.
         */
        citation: async function() {
            return certificateCitation;
        },

        /**
         * This function generates a new public-private key pair and uses the private key as the
         * new notary key. It returns the new public notary certificate.
         * 
         * NOTE: Ideally, it would make more sense for most of this method to be moved to the
         * <code>DigitalNotary</code> class but it can't be moved there because during regeneration
         * the old key key must sign the new certificate and the old key goes away right after the
         * new one is generated.
         * 
         * @returns {Catalog} The new notary certificate.
         */
        generate: async function() {
            try {
                const isRegeneration = !!privateKey;

                // generate a new public-private key pair
                const curve = crypto.createECDH(HSMPublic.CURVE);
                curve.generateKeys();
                notaryTag = notaryTag || bali.tag();  // generate a new tag if necessary
                version = version ? bali.version.nextVersion(version) : bali.version();
                timestamp = bali.moment();
                publicKey = curve.getPublicKey();

                // generate the new notary certificate
                const component = bali.catalog({
                    $protocol: HSMPublic.protocol,
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
                notaryCertificate.setValue('$protocol', HSMPublic.protocol);
                notaryCertificate.setValue('$timestamp', bali.moment());  // now
                if (previous) notaryCertificate.setValue('$previous', previous);
                notaryCertificate.setValue('$component', component);
                if (citation) notaryCertificate.setValue('$citation', citation);
                const signature = await this.sign(notaryCertificate);
                notaryCertificate.setValue('$signature', signature);

                // save the new key
                privateKey = curve.getPrivateKey();

                // cache the new certificate citation
                const digest = HSMPublic.digest(notaryCertificate);
                certificateCitation = HSMPublic.citation(notaryTag, version, digest);

                // save the state of this notary key and certificate in the local configuration
                try {
                    const notaryKey = bali.catalog({
                        $protocol: HSMPublic.protocol,
                        $timestamp: timestamp,
                        $account: account,
                        $publicKey: bali.binary(publicKey),
                        $privateKey: bali.binary(privateKey),
                        $citation: certificateCitation
                    }, bali.parameters({
                        $tag: notaryTag,
                        $version: version
                    }));
                    const keySource = notaryKey.toString() + EOL;  // add POSIX compliant <EOL>
                    const certificateSource = notaryCertificate.toString() + EOL;  // add POSIX compliant <EOL>
                    await pfs.writeFile(keyFilename, keySource, {encoding: 'utf8', mode: 0o600});
                    await pfs.writeFile(certificateFilename, certificateSource, {encoding: 'utf8', mode: 0o600});
                } catch (cause) {
                    const exception = bali.exception({
                        $module: '$HSMTest',
                        $function: '$generate',
                        $exception: '$directoryAccess',
                        $account: account || bali.NONE,
                        $text: bali.text('The configuration directory could not be accessed.')
                    }, cause);
                    throw exception;
                }

                return notaryCertificate;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$HSMTest',
                    $function: '$generate',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to (re)generate the key pair.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function causes the notary key to forget all information it knows about the
         * current public-private key pair.
         */
        forget: async function() {
            try {
                version = undefined;
                publicKey = undefined;
                privateKey = undefined;
                certificateCitation = undefined;
                notaryCertificate = undefined;
                // remove the configuration files
                await pfs.unlink(keyFilename).catch(function() {});
                await pfs.unlink(certificateFilename).catch(function() {});
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$HSMTest',
                    $function: '$forget',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to forget the current key pair.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function generates a digital signature of the specified component using the 
         * notary key. The resulting digital signature is base 32 encoded and may be verified
         * using the HSMPublic.verify() method and the corresponding public key.
         * 
         * @param {Component} component The component to be digitally signed.
         * @returns {Binary} A base 32 encoded digital signature of the component.
         */
        sign: async function(component) {
            try {
                const string = component.toString();  // force it to a string if it isn't already
                const curve = crypto.createECDH(HSMPublic.CURVE);
                curve.setPrivateKey(privateKey);
                const pem = ec_pem(curve, HSMPublic.CURVE);
                const signer = crypto.createSign(HSMPublic.SIGNATURE);
                signer.update(string);
                const signature = signer.sign(pem.encodePrivateKey());
                const binary = bali.binary(signature);
                return binary;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$HSMTest',
                    $function: '$sign',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $component: component || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to digitally sign a component.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function uses the notary key to decrypt the specified authenticated
         * encrypted message (AEM). The result is the decrypted component.
         * 
         * @param {Catalog} aem The authenticated encrypted message to be decrypted.
         * @returns {String} The decrypted component.
         */
        decrypt: async function(aem) {
            try {
                const seed = aem.getValue('$seed').getValue();
                const iv = aem.getValue('$iv').getValue();
                const auth = aem.getValue('$auth').getValue();
                const ciphertext = aem.getValue('$ciphertext').getValue();

                // decrypt the 32-byte symmetric key
                const curve = crypto.createECDH(HSMPublic.CURVE);
                curve.setPrivateKey(privateKey);
                const symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

                // decrypt the ciphertext using the symmetric key
                const decipher = crypto.createDecipheriv(HSMPublic.CIPHER, symmetricKey, iv);
                decipher.setAuthTag(auth);
                var plaintext = decipher.update(ciphertext, undefined, 'utf8');
                plaintext += decipher.final('utf8');
                const component = bali.parse(plaintext);
                return component;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$HSMTest',
                    $function: '$decrypt',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $aem: aem || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to decrypt an authenticated encrypted message.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        }
    };
};


const doesExist = async function(path) {
    var exists = true;
    await pfs.stat(path).catch(function(exception) {
        if (exception.code === 'ENOENT') {
            exists = false;
        } else {
            throw exception;
        }
    });
    return exists;
};
