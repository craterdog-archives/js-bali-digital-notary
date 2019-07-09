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
 * This module uses the singleton pattern to provide an object that implements a software
 * security module (SSM) for all cryptographic operations.  A more secure solution would
 * be to use a module that acts as a proxy to a tamper-proof hardware security module (HSM).
 */
const pfs = require('fs').promises;
const hasher = require('crypto');
const signer = require('tweetnacl').sign;


// PUBLIC API

/**
 * This function returns a singleton object that implements the API for the software
 * security module (SSM).
 *
 * @param {String} keyFile An optional file in the local directory that contains the
 * key information. If not specified, this API can only be used to perform public
 * key based functions.
 * @returns {Object} An object that implements the security module API.
 */
exports.api = function(keyFile) {
    var keys, oldKeys;

    return {

        /**
         * This function returns a string describing the attributes of the SSM.
         * 
         * @returns {String} A string describing the attributes of the SSM.
         */
        toString: function() {
            const string =
                '[\n' +
                '    $module: /bali/notary/' + PROTOCOL + '/SSM\n' +
                '    $protocol: ' + PROTOCOL + '\n' +
                '    $digest: "' + DIGEST + '"\n' +
                '    $signature: "' + SIGNATURE + '"\n' +
                ']';
            return string;
        },

        /**
         * This function returns the version of the security protocol supported by this
         * security module.
         * 
         * @returns {String} The version of the security protocol supported by this security
         * module.
         */
        getProtocol: function() {
            return PROTOCOL;
        },

        /**
         * This function initializes the API when a keyFile has been specified.
         */
        initializeAPI: keyFile ? async function() {
            try {
                // read in the keys (if possible)
                if (await doesExist(keyFile)) {
                    const data = JSON.parse(await pfs.readFile(keyFile, 'utf8'));
                    keys = {
                        privateKey: Buffer.from(data.privateKey),
                        publicKey: Buffer.from(data.publicKey)
                    };
                }
                this.initializeAPI = undefined;  // can only be called successfully once
            } catch (cause) {
                throw Error('The keys could not be loaded: ' + cause);
            }
        } : undefined,

        /**
         * This function generates a new public-private key pair.
         * 
         * @returns {Buffer} A byte buffer containing the new public key.
         */
        generateKeyPair: async function() {
            if (this.initializeAPI) await this.initializeAPI();
            try {
                oldKeys = keys;
                keys = generateKeyPair();
                const data = {
                    privateKey: keys.privateKey.toJSON().data,
                    publicKey: keys.publicKey.toJSON().data
                };
                await pfs.writeFile(keyFile, JSON.stringify(data, null, 4), 'utf8');
                return keys.publicKey;
            } catch (cause) {
                throw Error('A new key pair could not be generated: ' + cause);
            }
        },

        /**
         * This function returns a cryptographically secure digital digest of the
         * specified message. The generated digital digest will always be the same
         * for the same message.
         *
         * @param {String} message The message to be digested.
         * @returns {Buffer} A byte buffer containing a digital digest of the message.
         */
        digestMessage: async function(message) {
            try {
                const digest = digestMessage(message);
                return digest;
            } catch (cause) {
                throw Error('A digest of the message could not be generated: ' + cause);
            }
        },

        /**
         * This function generates a digital signature of the specified message using
         * the current private key (or the old private key, one time only, if it exists).
         * This allows a new certificate to be signed using the previous private key.
         * The resulting digital signature can then be verified using the corresponding
         * public key.
         * 
         * @param {String} message The message to be digitally signed.
         * @returns {Buffer} A byte buffer containing the resulting digital signature.
         */
        signMessage: async function(message) {
            if (this.initializeAPI) await this.initializeAPI();
            try {
                var signature;
                if (oldKeys) {
                    // the message is a certificate containing the new public key, so sign
                    // it using the old private key to enforce a valid certificate chain
                    signature = signMessage(message, oldKeys.privateKey);
                    oldKeys = undefined;
                } else {
                    signature = signMessage(message, keys.privateKey);
                }
                return signature;
            } catch (cause) {
                throw Error('A digital signature of the message could not be generated: ' + cause);
            }
        },

        /**
         * This function uses the specified public key to determine whether or not
         * the specified digital signature was generated using the corresponding
         * private key on the specified message.
         *
         * @param {String} message The digitally signed message.
         * @param {Buffer} publicKey A byte buffer containing the public key.
         * @param {Buffer} signature A byte buffer containing the digital signature
         * allegedly generated using the corresponding private key.
         * @returns {Boolean} Whether or not the digital signature is valid.
         */
        signatureIsValid: async function(message, publicKey, signature) {
            try {
                const result = signatureIsValid(message, publicKey, signature);
                return result;
            } catch (cause) {
                throw Error('The digital signature of the message could not be validated: ' + cause);
            }
        },

        /**
         * This function deletes any existing public-private key pairs.
         */
        deleteKeyPair: async function() {
            keys = undefined;
            oldKeys = undefined;
        }

    };
};


// PRIVATE CONSTANTS

// The algorithms for this version of the protocol
const PROTOCOL = 'v1';
const DIGEST = 'sha512';
const SIGNATURE = 'ed25519';


// PRIVATE FUNCTIONS

/**
 * This function determines whether or not the specified file exists.
 * 
 * @param {String} file The file to be checked.
 * @returns {Boolean} Whether or not the specified file exists.
 */
const doesExist = async function(file) {
    if (!file) return false;
    try {
        await pfs.stat(file);
        return true;
    } catch (exception) {
        if (exception.code === 'ENOENT') {
            return false;
        } else {
            throw exception;
        }
    }
};


/**
 * This function generates a new public-private key pair.
 * 
 * @returns {Object} An object containing the new public and private keys.
 */
const generateKeyPair = function() {
    const keys = signer.keyPair();
    return {
        publicKey: Buffer.from(keys.publicKey),
        privateKey: Buffer.from(keys.secretKey)
    };
};


/**
 * This function returns a cryptographically secure digital digest of the
 * specified message. The generated digital digest will always be the same
 * for the same message.
 *
 * @param {String} message The message to be digested.
 * @returns {Buffer} A byte buffer containing a digital digest of the message.
 */
const digestMessage = function(message) {
    const hash = hasher.createHash(DIGEST);
    hash.update(message);
    const digest = hash.digest();
    return digest;
};


/**
 * This function generates a digital signature of the specified message using
 * the specified private key. The resulting digital signature can then be
 * verified using the corresponding public key.
 * 
 * @param {String} message The message to be digitally signed.
 * @param {Buffer} privateKey A byte buffer containing the private key.
 * @returns {Buffer} A byte buffer containing the resulting digital signature.
 */
const signMessage = function(message, privateKey) {
    const signature = Buffer.from(signer.detached(Buffer.from(message, 'utf8'), privateKey));
    return signature;
};


/**
 * This function uses the specified public key to determine whether or not
 * the specified digital signature was generated using the corresponding
 * private key on the specified message.
 *
 * @param {String} message The digitally signed message.
 * @param {Buffer} publicKey A byte buffer containing the public key.
 * @param {Buffer} signature A byte buffer containing the digital signature
 * allegedly generated using the corresponding private key.
 * @returns {Boolean} Whether or not the digital signature is valid.
 */
const signatureIsValid = function(message, publicKey, signature) {
    const isValid = signer.detached.verify(Buffer.from(message, 'utf8'), signature, publicKey);
    return isValid;
};
