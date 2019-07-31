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


// PRIVATE CONSTANTS

// The algorithms for this version of the protocol
const PROTOCOL = 'v1';
const DIGEST = 'sha512';
const SIGNATURE = 'ed25519';


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
    var keys, previousKeys;

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
                        publicKey: Buffer.from(data.publicKey),
                        privateKey: Buffer.from(data.privateKey)
                    };
                }
                this.initializeAPI = undefined;  // can only be called successfully once
            } catch (cause) {
                throw Error('The keys could not be loaded: ' + cause.message);
            }
        } : undefined,

        /**
         * This function returns a cryptographically secure digital digest of the
         * specified bytes. The generated digital digest will always be the same
         * for the same bytes.
         *
         * @param {String} bytes The bytes to be digested.
         * @returns {Buffer} A byte buffer containing a digital digest of the bytes.
         */
        digestBytes: async function(bytes) {
            try {
                if (this.initializeAPI) await this.initializeAPI();
                const hash = hasher.createHash(DIGEST);
                hash.update(bytes);
                const digest = hash.digest();
                return digest;
            } catch (cause) {
                throw Error('A digest of the bytes could not be generated: ' + cause);
            }
        },

        /**
         * This function generates a new public-private key pair.
         * 
         * @returns {Buffer} A byte buffer containing the new public key.
         */
        generateKeys: async function() {
            try {
                if (this.initializeAPI) await this.initializeAPI();
                const raw = signer.keyPair();
                previousKeys = keys;
                keys = {
                    publicKey: Buffer.from(raw.publicKey),
                    privateKey: Buffer.from(raw.secretKey)
                };
                const data = {
                    publicKey: keys.publicKey.toJSON().data,
                    privateKey: keys.privateKey.toJSON().data
                };
                await pfs.writeFile(keyFile, JSON.stringify(data, null, 4), 'utf8');
                return keys.publicKey;
            } catch (cause) {
                throw Error('A new key pair could not be generated: ' + cause);
            }
        },

        /**
         * This function generates a digital signature of the specified bytes using
         * the current private key (or the old private key, one time only, if it exists).
         * This allows a new certificate to be signed using the previous private key.
         * The resulting digital signature can then be verified using the corresponding
         * public key.
         * 
         * @param {String} bytes The bytes to be digitally signed.
         * @returns {Buffer} A byte buffer containing the resulting digital signature.
         */
        signBytes: async function(bytes) {
            try {
                if (this.initializeAPI) await this.initializeAPI();
                var signature;
                if (previousKeys) {
                    // the bytes is a certificate containing the new public key, so sign
                    // it using the old private key to enforce a valid certificate chain
                    signature = Buffer.from(signer.detached(bytes, previousKeys.privateKey));
                    previousKeys = undefined;
                } else {
                    signature = Buffer.from(signer.detached(bytes, keys.privateKey));
                }
                return signature;
            } catch (cause) {
                throw Error('A digital signature of the bytes could not be generated: ' + cause);
            }
        },

        /**
         * This function uses the specified public key to determine whether or not
         * the specified digital signature was generated using the corresponding
         * private key on the specified bytes.
         *
         * @param {String} bytes The digitally signed bytes.
         * @param {Buffer} signature A byte buffer containing the digital signature
         * allegedly generated using the corresponding private key.
         * @param {Buffer} aPublicKey An optional byte buffer containing the public
         * key to be used to validate the signature. If none is specified, the
         * current public key for this security module is used.
         * @returns {Boolean} Whether or not the digital signature is valid.
         */
        validSignature: async function(bytes, signature, aPublicKey) {
            try {
                if (this.initializeAPI) await this.initializeAPI();
                aPublicKey = aPublicKey || keys.publicKey;
                const isValid = signer.detached.verify(bytes, signature, aPublicKey);
                return isValid;
            } catch (cause) {
                throw Error('The digital signature of the bytes could not be validated: ' + cause);
            }
        },

        /**
         * This function deletes any existing public-private key pairs.
         * 
         * @returns {Boolean} Whether or not the keys were successfully erased.
         */
        eraseKeys: async function() {
            try {
                if (this.initializeAPI) await this.initializeAPI();
                keys = undefined;
                previousKeys = undefined;
                return true;
            } catch (cause) {
                throw Error('The keys could not be erased: ' + cause);
            }
        }

    };
};


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
