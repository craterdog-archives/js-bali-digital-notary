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

const SSMv2 = require('./src/v2/SSM').SSM;
const DigitalNotary = require('./src/DigitalNotary').DigitalNotary;


/**
 * This function returns an object that implements the API for a software security module.
 *
 * @param {String} directory An optional directory to be used for local configuration storage.
 * @param {Boolean|Number} debug An optional number in the range 0..3 that controls
 * the level of debugging that occurs:
 * <pre>
 *   0 (or false): debugging turned off
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} An object that implements the API for a software security module.
 */
const ssmV2 = function(directory, debug) {
    const ssm = new SSMv2(directory, debug);
    return ssm;
};
exports.ssmV2 = ssmV2;


/**
 * This function returns an object that implements the API for a digital notary including
 * the functions that require access to the private key.
 *
 * @param {Object} securityModule An object that implements the security module interface.
 * @param {Tag} account A unique account tag for the owner of the digital notary.
 * @param {String} directory An optional directory to be used for local configuration storage.
 * @param {Boolean|Number} debug An optional number in the range 0..3 that controls
 * the level of debugging that occurs:
 * <pre>
 *   0 (or false): debugging turned off
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} An object that implements the API for a digital notary.
 */
const notary = function(securityModule, account, directory, debug) {
    const notary = new DigitalNotary(securityModule, account, directory, debug);
    return notary;
};
exports.notary = notary;


/**
 * This function initializes a digital notary test implementation configured with a local software
 * security module (SSM). It should ONLY be used for testing purposes.
 *
 * @param {Tag} account A unique tag for the account of the owner of the digital notary.
 * @param {String} directory The top level directory to be used for local configuration.
 * @param {Boolean|Number} debug An optional number in the range 0..3 that controls the level of
 * debugging that occurs:
 * <pre>
 *   0 (or false): no logging
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} The new digital notary test instance.
 */
const test = function(account, directory, debug) {
    return notary(ssmV2(directory, debug), account, directory, debug);
};
exports.test = test;


/**
 * This function initializes a digital notary instance configured to be used within a service
 * for public notary certificate based operations only.  No private notary key should be
 * generated for this instance.
 *
 * @param {Boolean|Number} debug An optional number in the range 0..3 that controls the level of
 * debugging that occurs:
 * <pre>
 *   0 (or false): no logging
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} The new digital notary service instance.
 */
const service = function(debug) {
    return notary(ssmV2(undefined, debug), undefined, undefined, debug);
};
exports.service = service;

