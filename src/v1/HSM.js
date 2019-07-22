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

/*
 * This module uses the singleton pattern to provide an object that acts as a PROXY to
 * a hardware security module (HSM) for all cryptographic operations.  All cryptographic
 * operations are initiated via bluetooth and performed on the actual HSM.
 */
const bluetooth = new (require('bluetooth-serial-port')).BluetoothSerialPort();


// PUBLIC API

/**
 * This function returns a singleton object that implements the API for the hardware
 * security module (HSM).
 *
 * @param {Buffer} secret A byte buffer containing 32 random bytes to be used to protect
 * the private key within the HSM when not in use.
 * @returns {Object} An object that implements the security module API.
 */
exports.api = function(secret) {

    return {

        /**
         * This function returns a string describing the attributes of the HSM.
         * 
         * @returns {String} A string describing the attributes of the HSM.
         */
        toString: function() {
            const string =
                '[\n' +
                '    $module: /bali/notary/HSM\n' +
                '    $protocol: v1\n' +
                '    $digest: "sha512"\n' +
                '    $signature: "sha512"\n' +
                ']';
        },

        /**
         * This function returns the version of the security protocol supported by this
         * security module.
         * 
         * @returns {String} The version of the security protocol supported by this security
         * module.
         */
        getProtocol: function() {
            return 'v1';
        },

        /**
         * This function initializes the API.
         */
        initializeAPI: async function() {
            try {
                throw Error('This function has not yet been implemented.');
                this.initializeAPI = undefined;  // can only be called once
            } catch (cause) {
                throw Error('The HSM could not be contacted: ' + cause);
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
            if (this.initializeAPI) await this.initializeAPI();
            try {
                throw Error('This function has not yet been implemented.');
            } catch (cause) {
                throw Error('A digest of the message could not be generated: ' + cause);
            }
        },

        /**
         * This function generates a new public-private key pair.
         * 
         * @returns {Buffer} A byte buffer containing the new public key.
         */
        generateKeys: async function() {
            if (this.initializeAPI) await this.initializeAPI();
            try {
                throw Error('This function has not yet been implemented.');
            } catch (cause) {
                throw Error('A new key pair could not be generated: ' + cause);
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
                throw Error('This function has not yet been implemented.');
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
         * @param {Buffer} signature A byte buffer containing the digital signature
         * allegedly generated using the corresponding private key.
         * @param {Buffer} aPublicKey An optional byte buffer containing the public
         * key to be used to validate the signature. If none is specified, the
         * current public key for this security module is used.
         * @returns {Boolean} Whether or not the digital signature is valid.
         */
        validSignature: async function(message, signature, aPublicKey) {
            if (this.initializeAPI) await this.initializeAPI();
            try {
                throw Error('This function has not yet been implemented.');
            } catch (cause) {
                throw Error('The digital signature of the message could not be validated: ' + cause);
            }
        },

        /**
         * This function deletes any existing public-private key pairs.
         */
        eraseKeys: async function() {
            throw Error('This function has not yet been implemented.');
        }

    };
};
