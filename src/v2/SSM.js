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
// This module should only be used for LOCAL TESTING, or on a PHYSICALLY SECURE      //
// device.  It CANNOT guarantee the protection of the private keys from people and   //
// other processes that have access to the RAM and storage devices for that device.  //
//                             YOU HAVE BEEN WARNED!!!                               //
///////////////////////////////////////////////////////////////////////////////////////

/*
 * This class implements a software security module that is capable of performing the following
 * functions:
 * <pre>
 *   * generateKeys - generate a new public-private key pair and return the public key
 *   * digestBytes - generate a cryptographic digest of an array of bytes
 *   * signBytes - digitally sign an array of bytes using the private key
 *   * validSignature - check whether or not the digital signature of an array of bytes is valid
 *   * rotateKeys - replace the existing public-private key pair with new pair
 *   * eraseKeys - erases any trace of the public-private key pair
 * </pre>
 */
const hasher = require('crypto');
const signer = require('supercop.js');
const bali = require('bali-component-framework').api();


// PRIVATE CONSTANTS

// the POSIX end of line character
const EOL = '\n';

// the algorithms for this version of the protocol
const PROTOCOL = 'v2';
const DIGEST = 'sha512';
const SIGNATURE = 'ed25519';

// define the finite state machine
const REQUESTS = [  //     possible request types
              '$generateKeys', '$signBytes', '$rotateKeys'
];
const STATES = {
//   current                allowed next states
    $keyless: [ '$loneKey',      undefined,    undefined  ],
    $loneKey: [  undefined,     '$loneKey',   '$twoKeys'  ],
    $twoKeys: [  undefined,     '$loneKey',    undefined  ]
};


// PUBLIC FUNCTIONS

/**
 * This function creates a new instance of a software security module (SSM).
 *
 * @param {String} directory An optional directory to be used for local configuration storage. If
 * no directory is specified, a directory called '.bali/' is created in the home directory.
 * @param {Boolean|Number} debug An optional number in the range [0..3] that controls the level of
 * debugging that occurs:
 * <pre>
 *   0 (or false): no logging
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} The new software security module.
 */
const SSM = function(directory, debug) {
    // validate the arguments
    if (debug === null || debug === undefined) debug = 0;  // default is off
    if (debug > 1) {
        const validator = bali.validator(debug);
        validator.validateType('/bali/notary/' + PROTOCOL + '/SSM', '$SSM', '$directory', directory, [
            '/javascript/Undefined',
            '/javascript/String'
        ]);
    }

    // setup the configuration
    const filename = 'SSM' + PROTOCOL + '.bali';
    const configurator = bali.configurator(filename, directory, debug);
    var configuration, controller;

    /**
     * This method returns a string describing the attributes of the SSM. It must not be an
     * asynchronous function since it is part of the JavaScript language.
     * 
     * @returns {String} A string describing the attributes of the SSM.
     */
    this.toString = function() {
        const catalog = bali.catalog({
            $module: '/bali/notary/' + PROTOCOL + '/SSM',
            $protocol: PROTOCOL,
            $digest: DIGEST,
            $signature: SIGNATURE
        });
        return catalog.toString();
    };

    /**
     * This method returns the unique tag for the security module.
     * 
     * @returns {Tag} The unique tag for the security module.
     */
    this.getTag = async function() {
        try {
            // load the current configuration if necessary
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getValue('$state').toString(), debug);
            }

            return configuration.getValue('$tag');
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/SSM',
                $procedure: '$getTag',
                $exception: '$unexpected',
                $text: 'The tag for the security module could not be retrieved.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };


    /**
     * This method returns the version of the security protocol supported by this
     * security module.
     * 
     * @returns {Version} The version string of the security protocol supported by this security
     * module.
     */
    this.getProtocol = async function() {
        try {
            return bali.component(PROTOCOL);
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/SSM',
                $procedure: '$getProtocol',
                $exception: '$unexpected',
                $text: 'The protocol supported by the security module could not be retrieved.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method generates a new public-private key pair.
     * 
     * @returns {Binary} A binary string containing the new public key.
     */
    this.generateKeys = async function() {
        try {
            // check the current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getValue('$state').toString(), debug);
            }
            controller.validateEvent('$generateKeys');

            // generate a new key pair
            const seed = signer.createSeed();
            const raw = signer.createKeyPair(seed);
            configuration.setValue('$publicKey', bali.binary(raw.publicKey));
            configuration.setValue('$privateKey', bali.binary(raw.secretKey));

            // update the configuration
            const state = controller.transitionState('$generateKeys');
            configuration.setValue('$state', state);
            await storeConfiguration(configurator, configuration, debug);

            return configuration.getValue('$publicKey');
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/SSM',
                $procedure: '$generateKeys',
                $exception: '$unexpected',
                $text: 'A new key pair could not be generated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method replaces the existing public-private key pair with a new one.
     * 
     * @returns {Binary} A binary string containing the new public key.
     */
    this.rotateKeys = async function() {
        try {
            // check the current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getValue('$state').toString(), debug);
            }
            controller.validateEvent('$rotateKeys');

            // save the previous key pair
            configuration.setValue('$previousPublicKey', configuration.getValue('$publicKey'));
            configuration.setValue('$previousPrivateKey', configuration.getValue('$privateKey'));

            // generate a new key pair
            const seed = signer.createSeed();
            const raw = signer.createKeyPair(seed);
            configuration.setValue('$publicKey', bali.binary(raw.publicKey));
            configuration.setValue('$privateKey', bali.binary(raw.secretKey));

            // update the configuration
            const state = controller.transitionState('$rotateKeys');
            configuration.setValue('$state', state);
            await storeConfiguration(configurator, configuration, debug);

            return configuration.getValue('$publicKey');
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/SSM',
                $procedure: '$rotateKeys',
                $exception: '$unexpected',
                $text: 'The key pair could not be rotated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method deletes any existing public-private key pairs.
     * 
     * @returns {Boolean} Whether or not the keys were successfully erased.
     */
    this.eraseKeys = async function() {
        try {
            // delete the current configuration
            await deleteConfiguration(configurator, debug);
            configuration = undefined;

            return true;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/SSM',
                $procedure: '$eraseKeys',
                $exception: '$unexpected',
                $text: 'The keys could not be erased.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method returns a cryptographically secure digital digest of the
     * specified bytes. The generated digital digest will always be the same
     * for the same bytes.
     *
     * @param {Buffer} bytes The bytes to be digested.
     * @returns {Binary} A binary string containing a digital digest of the bytes.
     */
    this.digestBytes = async function(bytes) {
        try {
            // validate the arguments
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/' + PROTOCOL + '/SSM', '$digestBytes', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }

            // generate the digital digest of the bytes
            const hash = hasher.createHash(DIGEST);
            hash.update(bytes);
            const digest = hash.digest();

            return bali.binary(digest);
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/SSM',
                $procedure: '$digestBytes',
                $exception: '$unexpected',
                $text: 'A digest of the bytes could not be generated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method generates a digital signature of the specified bytes using
     * the current private key (or the old private key, one time only, if it exists).
     * This allows a new certificate to be signed using the previous private key.
     * The resulting digital signature can then be verified using the corresponding
     * public key.
     * 
     * @param {Buffer} bytes The bytes to be digitally signed.
     * @returns {Binary} A binary string containing the resulting digital signature.
     */
    this.signBytes = async function(bytes) {
        try {
            // validate the arguments
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/' + PROTOCOL + '/SSM', '$signBytes', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }

            // check the current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getValue('$state').toString(), debug);
            }
            controller.validateEvent('$signBytes');

            // retrieve the keys
            var privateKey;
            var publicKey = configuration.getValue('$previousPublicKey');
            if (publicKey) {
                // the bytes define a certificate containing the new public key, so sign
                // it using the old private key to enforce a valid certificate chain
                privateKey = configuration.getValue('$previousPrivateKey');
                configuration.removeValues(['$previousPublicKey', '$previousPrivateKey']);
            } else {
                publicKey = configuration.getValue('$publicKey');
                privateKey = configuration.getValue('$privateKey');
            }

            // digitally sign the bytes using the private key
            const signature = signer.sign(bytes, publicKey.getValue(), privateKey.getValue());

            // update the configuration
            const state = controller.transitionState('$signBytes');
            configuration.setValue('$state', state);
            await storeConfiguration(configurator, configuration, debug);

            return bali.binary(signature);
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/SSM',
                $procedure: '$signBytes',
                $exception: '$unexpected',
                $text: 'A digital signature of the bytes could not be generated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method uses the specified public key to determine whether or not
     * the specified digital signature was generated using the corresponding
     * private key on the specified bytes.
     *
     * @param {Binary} aPublicKey A binary string containing the public key to be
     * used to validate the signature.
     * @param {Binary} signature A binary string containing the digital signature
     * allegedly generated using the corresponding private key.
     * @param {Buffer} bytes The digitally signed bytes.
     * @returns {Boolean} Whether or not the digital signature is valid.
     */
    this.validSignature = async function(aPublicKey, signature, bytes) {
        try {
            // validate the arguments
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/' + PROTOCOL + '/SSM', '$validSignature', '$aPublicKey', aPublicKey, [
                    '/bali/elements/Binary'
                ]);
                validator.validateType('/bali/notary/' + PROTOCOL + '/SSM', '$validSignature', '$signature', signature, [
                    '/bali/elements/Binary'
                ]);
                validator.validateType('/bali/notary/' + PROTOCOL + '/SSM', '$validSignature', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }

            // check the signature on the bytes
            const isValid = signer.verify(signature.getValue(), bytes, aPublicKey.getValue());

            return isValid;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/' + PROTOCOL + '/SSM',
                $procedure: '$validSignature',
                $exception: '$unexpected',
                $text: 'The digital signature of the bytes could not be validated.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    return this;
};
SSM.prototype.constructor = SSM;
exports.SSM = SSM;


// PRIVATE FUNCTIONS

/**
 * This function uses a configurator to store out the specified configuration catalog to
 * the local filesystem.
 * 
 * @param {Configurator} configurator A filesystem backed configurator.
 * @param {Catalog} configuration A catalog containing the current configuration to be stored.
 * @param {Boolean|Number} debug An optional number in the range [0..3] that controls
 * the level of debugging that occurs:
 */
const storeConfiguration = async function(configurator, configuration, debug) {
    try {
        await configurator.store(configuration.toString() + EOL);
    } catch (cause) {
        const exception = bali.exception({
            $module: '/bali/notary/' + PROTOCOL + '/SSM',
            $procedure: '$storeConfiguration',
            $exception: '$storageException',
            $text: 'The attempt to store the current configuration failed.'
        }, cause);
        if (debug > 0) console.error(exception.toString());
        throw exception;
    }
};


/**
 * This function uses a configurator to load the current configuration catalog from
 * the local filesystem.
 * 
 * @param {Configurator} configurator A filesystem backed configurator.
 * @param {Boolean|Number} debug An optional number in the range [0..3] that controls
 * the level of debugging that occurs:
 * @returns {Catalog} A catalog containing the current configuration.
 */
const loadConfiguration = async function(configurator, debug) {
    try {
        var configuration;
        const source = await configurator.load();
        if (source) {
            configuration = bali.component(source);
        } else {
            configuration = bali.catalog({
                $tag: bali.tag(),  // new random tag
                $state: '$keyless'
            });
            await configurator.store(configuration.toString() + EOL);
        }
        return configuration;
    } catch (cause) {
        const exception = bali.exception({
            $module: '/bali/notary/' + PROTOCOL + '/SSM',
            $procedure: '$loadConfiguration',
            $exception: '$storageException',
            $text: 'The attempt to load the current configuration failed.'
        }, cause);
        if (debug > 0) console.error(exception.toString());
        throw exception;
    }
};


/**
 * This function uses a configurator to delete the current configuration catalog from
 * the local filesystem.
 * 
 * @param {Configurator} configurator A filesystem backed configurator.
 * @param {Boolean|Number} debug An optional number in the range [0..3] that controls
 * the level of debugging that occurs:
 */
const deleteConfiguration = async function(configurator, debug) {
    try {
        await configurator.delete();
    } catch (cause) {
        const exception = bali.exception({
            $module: '/bali/notary/' + PROTOCOL + '/SSM',
            $procedure: '$deleteConfiguration',
            $exception: '$storageException',
            $text: 'The attempt to delete the current configuration failed.'
        }, cause);
        if (debug > 0) console.error(exception.toString());
        throw exception;
    }
};
