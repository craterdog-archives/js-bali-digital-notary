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
const HSMPublic = require('./HSMPublic');


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

    var notaryTag = bali.tag();          // the unique tag for the notary key
    var version = bali.version();        // the current version of the notary key
    var timestamp = bali.moment();       // the timestamp of when the key was generated
    var notaryCertificate = bali.NONE;   // the public notary certificate containing the public key
    var certificateCitation= bali.NONE;  // a document citation for the public notary certificate
    
    return {

        /**
         * This function returns a string providing attributes about this test HSM.
         * 
         * @returns {String} A string providing attributes about this test HSM.
         */
        toString: function() {
            const catalog = bali.catalog({
                $module: '$HSMProxy',
                $account: account,
                $timestamp: timestamp,
                $certificate: notaryCertificate,
                $citation: certificateCitation
            }, bali.parameters({
                $tag: notaryTag,
                $version: version
            }));
            return catalog.toString();
        },

        /**
         * This function initializes the API.
         */
        initialize: async function() {
            throw new Error('BUG: The following method has not yet been implemented: initialize()');
        },

        /**
         * This function returns the notary certificate associated with this notary key.
         * 
         * @returns {Catalog} The notary certificate associated with this notary key.
         */
        certificate: async function() {
            throw new Error('BUG: The following method has not yet been implemented: certificate()');
        },

        /**
         * This function returns a citation referencing the notary certificate associated
         * with this notary key.
         * 
         * @returns {Catalog} A citation referencing the notary certificate associated
         * with this notary key.
         */
        citation: async function() {
            throw new Error('BUG: The following method has not yet been implemented: citation()');
        },

        /**
         * This function generates a new public-private key pair and uses the private key as the
         * new notary key. It returns the new public notary certificate.
         * 
         * @returns {Catalog} The new notary certificate.
         */
        generate: async function() {
            throw new Error('BUG: The following method has not yet been implemented: generate()');
        },

        /**
         * This function causes the notary key to forget all information it knows about the
         * current public-private key pair.
         */
        forget: async function() {
            throw new Error('BUG: The following method has not yet been implemented: forget()');
        },

        /**
         * This function generates a digital signature of the specified component using the 
         * notary key. The resulting digital signature is base 32 encoded and may be verified
         * using the HSMPublic.verify() method and the corresponding public key.
         * 
         * @param {Component} component The component to be digitally signed.
         * @returns {Binary} A base 32 encoded digital signature of the component.
         */
        sign: async function(component) {
            throw new Error('BUG: The following method has not yet been implemented: sign(component)');
        },

        /**
         * This function uses the notary key to decrypt the specified authenticated
         * encrypted message (AEM). The result is the decrypted component.
         * 
         * @param {Catalog} aem The authenticated encrypted message to be decrypted.
         * @returns {String} The decrypted component.
         */
        decrypt: async function(aem) {
            throw new Error('BUG: The following method has not yet been implemented: decrypt(aem)');
        }
    };
};
