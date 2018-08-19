/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/


/**
 * This function returns a proxy to the hardward security module managing the private key
 * for the specified tag.
 * 
 * @param {String} tag The unique tag for the hardware security module.
 * @returns {Object} A proxy to the hardware security module managing the private key.
 */
exports.getNotaryKey = function(tag) {
    
    return {

        tag: tag,  // TODO: do we want to keep this or not (zero information)?

        toString: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'toString()');
        },

        generate: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'generate()');
        },

        regenerate: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'regenerate()');
        },

        forget: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'forget()');
        },

        reference: function() {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'reference()');
        },

        sign: function(document) {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'sign()');
        },

        certify: function(tag, version, publicKey) {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'certify()');
        },

        decrypt: function(aem) {
            throw new Error('NOTARY: The following method has not yet been implemented: ' + 'decrypt()');
        }
    };
};
