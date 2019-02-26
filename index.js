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
 * This function initializes the digital notary API. If a test directory
 * is passed in as a parameter the test directory will be used to maintain
 * the configuration file. Otherwise, the configuration file will be in the
 * '~/.bali/' directory. When running in test mode, a local software security
 * module will be used instead of a remote hardware security module (HSM)
 * for all operations that utilize the private notary key.
 * 
 * @param {Tag} account The unique tag for the account that owns the notary key.
 * @param {String} testDirectory The optional local directory to be used to 
 * maintain the configuration information for the digital notary API.
 * @returns {Object} A singleton object containing the initialized digital notary API.
 */
exports.api = function(account, testDirectory) {
    const api = require('./src/DigitalNotary').api(account, testDirectory);
    return api;
};
