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
const crypto = require('crypto');
const bluetooth = require('@abandonware/noble');


// PRIVATE CONSTANTS

// The algorithms for this version of the protocol
const PROTOCOL = 'v1';
const DIGEST = 'sha512';
const SIGNATURE = 'ed25519';

// These are viewed from the client (mobile device) perspective
const UART_SERVICE_ID = '6e400001b5a3f393e0a9e50e24dcca9e';
const UART_WRITE_ID = '6e400002b5a3f393e0a9e50e24dcca9e';
const UART_NOTIFICATION_ID = '6e400003b5a3f393e0a9e50e24dcca9e';


// PUBLIC API

/**
 * This function returns a singleton object that implements the API for the hardware
 * security module (HSM).
 *
 * @returns {Object} An object that implements the security module API.
 */
exports.api = function() {
    var peripheral;
    var secret, previousSecret;

    return {

        /**
         * This function returns a string describing the attributes of the HSM.
         * 
         * @returns {String} A string describing the attributes of the HSM.
         */
        toString: function() {
            const string =
                '[\n' +
                '    $module: /bali/notary/' + PROTOCOL + '/HSM\n' +
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
         * This function initializes the API.
         */
        initializeAPI: async function() {
            peripheral = await findPeripheral();
            this.initializeAPI = undefined;  // can only be called successfully once
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
                if (this.initializeAPI) await this.initializeAPI();
                const request = formatRequest('digestMessage', Buffer.from(message, 'utf8'));
                const digest = await processRequest(peripheral, request);
                return digest;
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
            try {
                if (this.initializeAPI) await this.initializeAPI();
                // TODO: erase previousSecret
                previousSecret = secret;
                secret = crypto.randomBytes(32);
                const request = formatRequest('generateKeys', secret);
                const publicKey = await processRequest(peripheral, request);
                return publicKey;
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
            try {
                if (this.initializeAPI) await this.initializeAPI();
                var request;
                if (previousSecret) {
                    request = formatRequest('signMessage', previousSecret, Buffer.from(message, 'utf8'));
                    // TODO: erase previousSecret
                    previousSecret = undefined;
                } else {
                    request = formatRequest('signMessage', secret, Buffer.from(message, 'utf8'));
                }
                const signature = await processRequest(peripheral, request);
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
         * @param {Buffer} signature A byte buffer containing the digital signature
         * allegedly generated using the corresponding private key.
         * @param {Buffer} aPublicKey An optional byte buffer containing the public
         * key to be used to validate the signature. If none is specified, the
         * current public key for this security module is used.
         * @returns {Boolean} Whether or not the digital signature is valid.
         */
        validSignature: async function(message, signature, aPublicKey) {
            try {
                if (this.initializeAPI) await this.initializeAPI();
                const request = formatRequest('validSignature', Buffer.from(message, 'utf8'), signature, aPublicKey);
                const isValid = (await processRequest(peripheral, request))[0] ? true : false;
                return isValid;
            } catch (cause) {
                throw Error('The digital signature of the message could not be validated: ' + cause);
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
                const request = formatRequest('eraseKeys');
                const succeeded = (await processRequest(peripheral, request))[0] ? true : false;
                return succeeded;
            } catch (cause) {
                throw Error('The keys could not be erased: ' + cause);
            }
        }

    };
};


// PRIVATE FUNCTIONS

/**
 * This function formats a request into a binary format prior to sending it via bluetooth.
 * Each request has the following byte format:
 *   Request (1 byte) [0..255]
 *   Number of Arguments (1 byte) [0..255]
 *   Length of Argument 1 (2 bytes) [0..65535]
 *   Argument 1 ([0..65535] bytes)
 *   Length of Argument 2 (2 bytes) [0..65535]
 *   Argument 2 ([0..65535] bytes)
 *      ...
 *   Length of Argument N (2 bytes) [0..65535]
 *   Argument N ([0..65535] bytes)
 *
 * If the entire request is only a single byte long then the number of arguments
 * is assumed to be zero.

 * @param {String} type The type of the request.
 * @param {Buffer} args Zero or more buffers containing the bytes for each argument.
 * @returns {Buffer} A buffer containing the bytes for the entire request.
 */
const formatRequest = function(type, ...args) {
    switch (type) {
        case 'digestMessage':
            type = 1;
            break;
        case 'generateKeys':
            type = 2;
            break;
        case 'signMessage':
            type = 3;
            break;
        case 'validSignature':
            type = 4;
            break;
        case 'eraseKeys':
            type = 5;
            break;
        case 'testHSM':
            type = 42;
            break;
    }
    var request = Buffer.from([type & 0xFF, args.length & 0xFF]);
    args.forEach(arg => {
        var length = arg.length;
        request = Buffer.concat([
            request,                                               // the request thus far
            Buffer.from([(length & 0xFF00) >> 8, length & 0xFF]),  // the length of this argument
            arg],                                                   // the argument bytes
            request.length + length + 2                            // the length of the new buffer
        );
    });
    return request;
};


const findPeripheral = function() {
    return new Promise(function(resolve, reject) {
        bluetooth.on('discover', function(peripheral) {
            const advertisement = peripheral.advertisement;
            console.log('Found a peripheral: ' + advertisement.localName);
            if (advertisement.localName === 'ButtonUp') {
                bluetooth.stopScanning();
                resolve(peripheral);
            }
        });
        console.log('Searching for an HSM...');
        bluetooth.startScanning([UART_SERVICE_ID]);  // start searching for an HSM (asynchronously)
    });
};


const processRequest = function(peripheral, request) {
    return new Promise(function(resolve, reject) {
        if (peripheral === undefined) reject('No HSM near by.');
        console.log('Attempting to connect...');
        peripheral.connect(function(cause) {
            if (!cause) {
                console.log('Successfully connected.');
                peripheral.discoverServices([UART_SERVICE_ID], function(cause, services) {
                    if (!cause && services.length === 1) {
                        services[0].discoverCharacteristics([], function(cause, characteristics) {
                            if (!cause) {
                                var input, output;
                                characteristics.forEach (characteristic => {
                                    // TODO: make it more robust by checking properties instead of Ids
                                    if (characteristic.uuid === UART_NOTIFICATION_ID) input = characteristic;
                                    if (characteristic.uuid === UART_WRITE_ID) output = characteristic;
                                });
                                if (input && output) {
                                    input.on('read', function(response, isNotification) {
                                        console.log('Received notification: ' + isNotification);
                                        if (response.length === 1) {
                                            const value = response.readUInt8(0);
                                            switch (value) {
                                                case 0:
                                                    response = false;
                                                    break;
                                                case 1:
                                                    response = true;
                                                    break;
                                                default:
                                                    response = Error('The request failed.');
                                            }
                                            console.log('response: ' + response);
                                        } else {
                                            console.log('response: ' + response.toString('hex'));
                                        }
                                        peripheral.disconnect(function() {
                                            console.log('Peripheral disconnected.');
                                            resolve(response);
                                        });
                                    });
                                    input.subscribe(function() {
                                        console.log('Notification subscription succeeded.');
                                        output.write(request, false, function() {
                                            console.log('Write completed.');
                                            // can't resolve it until the response is read
                                        });
                                    });
                                }
                            } else {
                                peripheral.disconnect(function() {
                                    reject(cause);
                                });
                            }
                        });
                    } else {
                        cause = cause || Error('Wrong number of UART services found.');
                        peripheral.disconnect(function() {
                            reject(cause);
                        });
                    }
                });
            } else {
                peripheral.disconnect(function() {
                    reject(cause);
                });
            }
        });
    });
};
