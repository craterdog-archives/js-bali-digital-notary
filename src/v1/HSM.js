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


// PUBLIC APIs

/**
 * This function returns an object that implements the API for the public hardware security
 * module (HSM).
 *
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} A proxy to the public hardware security module.
 */
exports.publicAPI = function(debug) {
    debug = debug || false;

    return {

        /**
         * This function returns a string providing attributes about this hardware security module.
         *
         * @returns {String} A string providing attributes about this hardware security module.
         */
        toString: function() {
        },

        /**
         * This function generates a document citation for the specified document.
         *
         * @param {Catalog} document The document to be cited.
         * @returns {Catalog} A document citation for the document.
         */
        citeDocument: function(document) {
        },

        /**
         * This function determines whether or not the specified document citation matches
         * the specified document. The citation only matches if its digest matches the
         * digest of the document exactly.
         *
         * @param {Catalog} citation A document citation allegedly referring to the
         * specified document.
         * @param {Catalog} document The document to be tested.
         * @returns {Boolean} Whether or not the citation matches the specified document.
         */
        citationMatches: function(citation, document) {
        },

        /**
         * This function determines whether or not the notary seal on the specified document
         * is valid.
         *
         * @param {Catalog} document The notarized document to be tested.
         * @param {Catalog} certificate A catalog containing the public certificate for the
         * private notary key that allegedly notarized the specified document.
         * @returns {Boolean} Whether or not the notary seal on the document is valid.
         */
        documentIsValid: function(document, certificate) {
        },

        /**
         * This function uses the specified public notary certificate to encrypt the specified
         * document in such a way that only the intended recipient of the encrypted document can
         * decrypt it using their private notary key. The result is an authenticated encrypted
         * message (AEM) containing the ciphertext and other required attributes needed to
         * decrypt the message.
         *
         * @param {Component} document The document to be encrypted using the specified
         * public notary certificate.
         * @param {Catalog} certificate A catalog containing the public certificate for the
         * intended recipient of the encrypted document.
         * @returns {Catalog} An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes for the encrypted document.
         */
        encryptDocument: function(document, certificate) {
        }
    };
};

/**
 * This function returns an object that implements the private key API for the proxy to
 * the hardware security module (HSM). 
 *
 * @param {Tag} account The unique tag for the account that owns the notary key.
 * @param {String} testDirectory An optional directory to use for local testing.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} A proxy to the test hardware security module managing the private key.
 */
exports.privateAPI = function(account, testDirectory, debug) {
    debug = debug || false;

    return {

        /**
         * This function returns a string providing attributes about this hardware security module.
         *
         * @returns {String} A string providing attributes about this hardware security module.
         */
        toString: function() {
        },

        /**
         * This function initializes the API.
         */
        initializeAPI: async function() {
        },

        /**
         * This function returns the notary certificate associated with this notary key.
         *
         * @returns {Catalog} The notary certificate associated with this notary key.
         */
        getCertificate: function() {
        },

        /**
         * This function returns a citation referencing the notary certificate associated
         * with this notary key.
         *
         * @returns {Catalog} A citation referencing the notary certificate associated
         * with this notary key.
         */
        getCitation: function() {
        },

        /**
         * This function generates a new public-private key pair and uses the private key as the
         * new notary key. It returns the new public notary certificate. Note, during regeneration
         * the old private key is used to sign the new certificate before it is destroyed.
         *
         * @returns {Catalog} The new notary certificate.
         */
        generateKey: async function() {
        },

        /**
         * This function causes the digital notary to forget all information
         * it knows about the current public-private key pair.
         */
        forgetKey: async function() {
        },

        /**
         * This function digitally notarizes the specified document using the private notary
         * key maintained inside the hardware security module. An optional document citation
         * to the previous version of the document may be specified. Also, an optional
         * document citation to a document defining the permissions for accessing the document
         * may be specified. If no permissions are specified, the document will be publicly
         * available to anyone. The newly notarized document is returned.
         *
         * @param {Component} document The document to be notarized.
         * @param {Catalog} previous An optional document citation to the previous version of
         * the document.
         * @param {Catalog} permissions An optional document citation to a document defining
         * the permissions for accessing the document.
         * @returns {Catalog} The newly notarized document.
         */
        notarizeDocument: function(document, previous, permissions) {
        },

        /**
         * This function uses the notary key to decrypt the specified authenticated
         * encrypted message (AEM). The result is the decrypted document.
         *
         * @param {Catalog} aem The authenticated encrypted message to be decrypted.
         * @returns {Component} The decrypted document.
         */
        decryptDocument: async function(aem) {
        }
    };
};
