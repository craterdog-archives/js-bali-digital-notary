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
 * This function returns an object that implements the public certificate API for
 * the digital notary. The public API only deals with public certificates and is
 * implemented using a software security module (SSM).
 *
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} A singleton object implementing the public API.
 */
exports.publicAPI = function(debug) {
    const api = require('./src/DigitalNotary').publicAPI(debug);
    return api;
};


/**
 * This function returns an object that implements the full API for the digital notary.
 * If a test directory is passed in as a parameter the test directory will be used
 * to maintain the configuration file. Otherwise, the configuration file will be in
 * the '~/.bali/' directory. When running in test mode, a local software security
 * module will be used instead of a remote hardware security module (HSM)
 * for all operations that utilize the private notary key.
 *
 * @param {Tag} accountId The unique account tag for the owner of the digital notary.
 * @param {String} directory The optional local directory to be used to
 * maintain the configuration information for the digital notary API.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} A singleton object implementing the private API.
 */
exports.api = function(accountId, directory, debug) {
    const api = require('./src/DigitalNotary').api(accountId, directory, debug);
    return api;
};
