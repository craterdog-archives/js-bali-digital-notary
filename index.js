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
 * An optional debug argument may be specified that controls the level of debugging that
 * should be applied during execution. The allowed levels are as follows:
 * <pre>
 *   0: no debugging is applied (this is the default value and has the best performance)
 *   1: log any exceptions to console.error before throwing them
 *   2: perform argument validation checks on each call (poor performance)
 *   3: log interesting arguments, states and results to console.log
 * </pre>
 *
 * @param {String} directory An optional directory to be used for local configuration storage.
 * @returns {Object} An object that implements the API for a software security module.
 */
const ssmV2 = function(directory, debug) {
    return new SSMv2(directory, debug);
};
exports.ssmV2 = ssmV2;


/**
 * This function returns an object that implements the API for a digital notary including
 * the functions that require access to the private key.
 *
 * An optional debug argument may be specified that controls the level of debugging that
 * should be applied during execution. The allowed levels are as follows:
 * <pre>
 *   0: no debugging is applied (this is the default value and has the best performance)
 *   1: log any exceptions to console.error before throwing them
 *   2: perform argument validation checks on each call (poor performance)
 *   3: log interesting arguments, states and results to console.log
 * </pre>
 *
 * @param {Object} securityModule An object that implements the security module interface.
 * @param {Tag} account A unique account tag for the owner of the digital notary.
 * @param {String} directory An optional directory to be used for local configuration storage.
 * @returns {Object} An object that implements the API for a digital notary.
 */
const notary = function(securityModule, account, directory, debug) {
    return new DigitalNotary(securityModule, account, directory, debug);
};
exports.notary = notary;


/**
 * This function initializes a digital notary test implementation configured with a local software
 * security module (SSM). It should ONLY be used for testing purposes.
 *
 * An optional debug argument may be specified that controls the level of debugging that
 * should be applied during execution. The allowed levels are as follows:
 * <pre>
 *   0: no debugging is applied (this is the default value and has the best performance)
 *   1: log any exceptions to console.error before throwing them
 *   2: perform argument validation checks on each call (poor performance)
 *   3: log interesting arguments, states and results to console.log
 * </pre>
 *
 * @param {Tag} account A unique tag for the account of the owner of the digital notary.
 * @param {String} directory The top level directory to be used for local configuration.
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
 * An optional debug argument may be specified that controls the level of debugging that
 * should be applied during execution. The allowed levels are as follows:
 * <pre>
 *   0: no debugging is applied (this is the default value and has the best performance)
 *   1: log any exceptions to console.error before throwing them
 *   2: perform argument validation checks on each call (poor performance)
 *   3: log interesting arguments, states and results to console.log
 * </pre>
 *
 * @returns {Object} The new digital notary service instance.
 */
const service = function(debug) {
    return notary(ssmV2(undefined, debug), undefined, undefined, debug);
};
exports.service = service;

