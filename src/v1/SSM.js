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
 * This class implements a software security module that is capable of performing the following functions:
 * <pre>
 *   * generateKeys - generate a new public-private key pair and return the public key
 *   * digestBytes - generate a cryptographic digest of an array of bytes
 *   * signBytes - digitally sign an array of bytes using the private key
 *   * signatureValid - check whether or not the digital signature of an array of bytes is valid
 *   * rotateKeys - replace the existing public-private key pair with new pair
 *   * eraseKeys - erases any trace of the public-private key pair
 * </pre>
 */
const hasher = require('crypto');
const signer = require('supercop.js');
const bali = require('bali-component-framework').api();
const EOL = '\n'; // The POSIX end of line character


// PRIVATE CONSTANTS

// The algorithms for this version of the protocol
const PROTOCOL = 'v1';
const DIGEST = 'sha512';
const SIGNATURE = 'ed25519';


// PUBLIC API

/**
 * This function creates a new instance of a software security module (SSM).
 *
 * @param {String} keyfile An optional filename of the file that contains the current
 * key information.  If not specified, this module can only be used to perform public key
 * based functions.
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
 * @returns {Object} An object that implements the security module API.
 */
function SSM(keyfile, directory, debug) {
    if (debug === null || debug === undefined) debug = 0;  // default is off
    if (debug > 1) {
        const validator = bali.validator(debug);
        validator.validateType('/bali/notary/SSM', '$SSM', '$keyfile', keyfile, [
            '/javascript/Undefined',
            '/javascript/String'
        ]);
        validator.validateType('/bali/notary/SSM', '$SSM', '$directory', directory, [
            '/javascript/Undefined',
            '/javascript/String'
        ]);
    }
    const configuration = bali.configuration(keyfile, directory, debug);
    var keys, previousKeys;

    /**
     * This method returns a string describing the attributes of the SSM.
     * 
     * @returns {String} A string describing the attributes of the SSM.
     */
    this.toString = function() {
        const string =
            '[\n' +
            '    $module: /bali/notary/' + PROTOCOL + '/SSM\n' +
            '    $protocol: ' + PROTOCOL + '\n' +
            '    $digest: "' + DIGEST + '"\n' +
            '    $signature: "' + SIGNATURE + '"\n' +
            ']';
        return string;
    };

    /**
     * This method returns the version of the security protocol supported by this
     * security module.
     * 
     * @returns {String} The version of the security protocol supported by this security
     * module.
     */
    this.getProtocol = function() {
        return PROTOCOL;
    };

    /**
     * This method generates a new public-private key pair.
     * 
     * @returns {Buffer} A byte buffer containing the new public key.
     */
    this.generateKeys = async function() {
        try {
            const seed = signer.createSeed();
            const raw = signer.createKeyPair(seed);
            keys = {
                publicKey: Buffer.from(raw.publicKey),
                privateKey: Buffer.from(raw.secretKey)
            };
            await storeKeys(configuration, keys);
            return keys.publicKey;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/v1/SSM',
                $procedure: '$generateKeys',
                $exception: '$unexpected',
                $text: bali.text('A new key pair could not be generated.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method replaces the existing public-private key pair with a new one.
     * 
     * @returns {Buffer} A byte buffer containing the new public key.
     */
    this.rotateKeys = async function() {
        try {
            keys = keys || await loadKeys(configuration);
            const seed = signer.createSeed();
            const raw = signer.createKeyPair(seed);
            previousKeys = keys;
            keys = {
                publicKey: Buffer.from(raw.publicKey),
                privateKey: Buffer.from(raw.secretKey)
            };
            await storeKeys(configuration, keys);
            return keys.publicKey;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/v1/SSM',
                $procedure: '$rotateKeys',
                $exception: '$unexpected',
                $text: bali.text('A new key pair could not be generated.')
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
            await deleteKeys(configuration);
            keys = undefined;
            previousKeys = undefined;
            return true;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/v1/SSM',
                $procedure: '$eraseKeys',
                $exception: '$unexpected',
                $text: bali.text('The keys could not be erased.')
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
     * @returns {Buffer} A byte buffer containing a digital digest of the bytes.
     */
    this.digestBytes = async function(bytes) {
        try {
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/SSM', '$digestBytes', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }
            const hash = hasher.createHash(DIGEST);
            hash.update(bytes);
            const digest = hash.digest();
            return digest;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/v1/SSM',
                $procedure: '$digestBytes',
                $exception: '$unexpected',
                $text: bali.text('A digest of the bytes could not be generated.')
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
     * @returns {Buffer} A byte buffer containing the resulting digital signature.
     */
    this.signBytes = async function(bytes) {
        try {
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/SSM', '$signBytes', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }
            keys = keys || await loadKeys(configuration);
            var signature;
            if (previousKeys) {
                // the bytes define a certificate containing the new public key, so sign
                // it using the old private key to enforce a valid certificate chain
                signature = Buffer.from(signer.sign(bytes, previousKeys.publicKey, previousKeys.privateKey));
                previousKeys = undefined;
            } else if (keys) {
                signature = Buffer.from(signer.sign(bytes, keys.publicKey, keys.privateKey));
            } else {
                throw Error('No keys exist.');
            }
            return signature;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/v1/SSM',
                $procedure: '$signBytes',
                $exception: '$unexpected',
                $text: bali.text('A digital signature of the bytes could not be generated.')
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
     * @param {Buffer} aPublicKey A byte buffer containing the public key to be
     * used to validate the signature.
     * @param {Buffer} signature A byte buffer containing the digital signature
     * allegedly generated using the corresponding private key.
     * @param {Buffer} bytes The digitally signed bytes.
     * @returns {Boolean} Whether or not the digital signature is valid.
     */
    this.validSignature = async function(aPublicKey, signature, bytes) {
        try {
            if (debug > 1) {
                const validator = bali.validator(debug);
                validator.validateType('/bali/notary/SSM', '$validSignature', '$aPublicKey', aPublicKey, [
                    '/nodejs/Buffer'
                ]);
                validator.validateType('/bali/notary/SSM', '$validSignature', '$signature', signature, [
                    '/nodejs/Buffer'
                ]);
                validator.validateType('/bali/notary/SSM', '$validSignature', '$bytes', bytes, [
                    '/nodejs/Buffer'
                ]);
            }
            const isValid = signer.verify(signature, bytes, aPublicKey);
            return isValid;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/v1/SSM',
                $procedure: '$validSignature',
                $exception: '$unexpected',
                $text: bali.text('The digital signature of the bytes could not be validated.')
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

const storeKeys = async function(configuration, keys) {
    const data = {
        publicKey: keys.publicKey.toJSON().data,
        privateKey: keys.privateKey.toJSON().data
    };
    await configuration.store(JSON.stringify(data, null, 4) + EOL);
};

const loadKeys = async function(configuration) {
    const json = await configuration.load();
    if (!json) return;
    const data = JSON.parse(json);
    const keys = {
        publicKey: Buffer.from(data.publicKey),
        privateKey: Buffer.from(data.privateKey)
    };
    return keys;
};

const deleteKeys = async function(configuration) {
    await configuration.delete();
};
