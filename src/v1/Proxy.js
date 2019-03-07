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
 * This module uses the singleton pattern to provide a proxy object that communicates
 * with a hardware security module (HSM) for all cryptographic operations involving the
 * associated private key. The private key itself is created on the HSM and never leaves
 * it.  All operations requiring the private key are performed in hardware on the HSM.
 */
const bali = require('bali-component-framework');
const Public = require('./Public');


/**
 * This function returns a proxy object that implements the API for the hardware security module
 * (notary private key) associated with the specified unique tag.
 * 
 * @param {Tag} account The unique tag for the account that owns the notary key.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} A proxy object to the hardware security module managing the private key.
 */
exports.api = function(account, debug) {
    debug = debug || false;

    // validate the parameters
    if (!account || !account.getTypeId || account.getTypeId() !== bali.types.TAG) {
        const exception = bali.exception({
            $module: '$v1Proxy',
            $function: '$api',
            $exception: '$invalidParameter',
            $parameter: account ? bali.text(account.toString()) : bali.NONE,
            $message: bali.text('The account tag is invalid.')
        });
        if (debug) console.error(exception.toString());
        throw exception;
    }
    
    return {

        toString: function() {
            throw new Error('BUG: The following method has not yet been implemented: toString()');
        },

        initialize: async function() {
            throw new Error('BUG: The following method has not yet been implemented: initialize()');
        },

        certificate: async function() {
            throw new Error('BUG: The following method has not yet been implemented: certificate()');
        },

        citation: async function() {
            throw new Error('BUG: The following method has not yet been implemented: citation()');
        },

        generate: async function() {
            throw new Error('BUG: The following method has not yet been implemented: generate()');
        },

        forget: async function() {
            throw new Error('BUG: The following method has not yet been implemented: forget()');
        },

        sign: async function(message) {
            throw new Error('BUG: The following method has not yet been implemented: sign(message)');
        },

        decrypt: async function(aem) {
            throw new Error('BUG: The following method has not yet been implemented: decrypt(aem)');
        }
    };
};
