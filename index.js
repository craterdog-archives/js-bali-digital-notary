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

/**
 * This function returns an object that implements the API for a software security module.
 * 
 * @param {String} keyfile An optional filename for a file containing the current key information.
 * If not specified, this API can only be used to perform public key based functions.
 * @param {String} directory An optional directory to be used for local configuration storage.
 * @param {Boolean|Number} debug An optional number in the range [0..3] that controls
 * the level of debugging that occurs:
 * <pre>
 *   0 (or false): debugging turned off
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} An object that implements the API for a software security module.
 */
exports.ssm = function(keyfile, directory, debug) {
    const ssm = new require('./src/v1/SSM').SSM(keyfile, directory, debug);
    return ssm;
};


/**
 * This function returns an object that implements the API for a digital notary including
 * the functions that require access to the private key.
 *
 * @param {Object} securityModule An object that implements the security module interface.
 * @param {Tag} account A unique account tag for the owner of the digital notary.
 * @param {String} directory An optional directory to be used for local configuration storage.
 * @param {Boolean|Number} debug An optional number in the range [0..3] that controls
 * the level of debugging that occurs:
 * <pre>
 *   0 (or false): debugging turned off
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.notary = function(securityModule, account, directory, debug) {
    const notary = new require('./src/DigitalNotary').DigitalNotary(securityModule, account, directory, debug);
    return notary;
};
