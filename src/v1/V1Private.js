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


/**
 * This function returns a proxy object that implements the API for the hardware security module
 * (notary key) associated with the specified unique tag.
 * 
 * @param {String} tag A unique tag identifying a specifice hardware security module.
 * @returns {Object} A proxy object to the hardware security module managing the private key.
 */
exports.notaryKey = function(tag) {
    
    return {

        toString: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'toString()');
        },

        toSource: function(indentation) {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'toString()');
        },

        certificate: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'generate()');
        },

        citation: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'generate()');
        },

        generate: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'generate()');
        },

        forget: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'forget()');
        },

        sign: function(document) {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'sign()');
        },

        decrypt: function(aem) {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'decrypt()');
        }
    };
};
