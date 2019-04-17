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
 * @param {Buffer} secret A byte buffer containing 32 random bytes that are used to help
 * protect the private key when not in use.
 * @param {String} keyfile An optional filename for a file containing the key information.
 * @returns {Object} An object that implements the API for a software security module.
 */
exports.ssm = function(secret, keyfile) {
    const securityModule = require('./src/v1/SSM').api(secret, keyfile);
    return securityModule;
};


/**
 * This function returns an object that implements the API for a hardware security module.
 * 
 * @param {Buffer} secret A byte buffer containing 32 random bytes that are used to help
 * protect the private key when not in use.
 * @returns {Object} An object that implements the API for a hardware security module.
 */
exports.hsm = function(secret) {
    const securityModule = require('./src/v1/HSM').api(secret);
    return securityModule;
};


/**
 * This function returns an object that implements the API for a digital notary including
 * the functions that require access to the private key.
 *
 * @param {Object} securityModule An object that implements the security module interface.
 * @param {Tag} accountId An optional unique account tag for the owner of the digital notary.
 * @param {String} directory An optional directory to be used for local configuration storage.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.api = function(securityModule, accountId, directory, debug) {
    const api = require('./src/DigitalNotary').api(securityModule, accountId, directory, debug);
    return api;
};
