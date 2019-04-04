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
 * This module uses the singleton pattern to expose two objects that implement
 * digital notary APIs that are used for document notarization purposes within
 * the Bali Nebula™. The first is a public API that can used by anyone to validate
 * existing notarized documents. The second is a private API that uses a hardware
 * security module to provide full digital signing capabilities associated with
 * a specific user account.
 */
const bali = require('bali-component-framework');
const protocols = {
//  ...
//  v3: require('./v3'),
//  v2: require('./v2'),
    v1: require('./v1')
};
const preferredProtocol = protocols[Object.keys(protocols)[0]];  // the first protocol


// PUBLIC APIs

/**
 * This function returns an object that implements the public certificate API for a
 * digital notary. It provides only the functions that don't require a private key and
 * can be used with any public certificates.
 *
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.publicAPI = function(debug) {

    // validate the parameters
    debug = debug || false;

    // setup the public API implementation
    const publicAPI = preferredProtocol.SSM.publicAPI(debug);

    // return a singleton object for the API
    return {
   
        /**
         * This function returns a string providing attributes about this software security module.
         *
         * @returns {String} A string providing attributes about this software security module.
         */
        toString: function() {
            return publicAPI.toString();
        },

        /**
         * This function returns a list of the protocol versions supported by this digital notary
         * API.
         * 
         * @returns {List} A list of the protocol versions supported by this digital notary API.
         */
        getProtocols: function() {
            return getProtocols(debug);
        },
   
        /**
         * This function generates a document citation for the specified document.
         *
         * @param {Catalog} document The document to be cited.
         * @returns {Catalog} A document citation for the document.
         */
        citeDocument: function(document) {
            return publicAPI.citeDocument(document);
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
            const api = getPublicAPI(debug, '$citationMatches', citation);
            return api.citationMatches(citation, document);
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
            const api = getPublicAPI(debug, '$documentIsValid', certificate);
            return api.documentIsValid(document, certificate);
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
            const api = getPublicAPI(debug, '$encryptDocument', certificate);
            return api.encryptDocument(document, certificate);
        }
   
    };
};


/**
 * This function returns an object that implements the full API for a digital notary.
 *
 * @param {Tag} account The unique account tag for the owner of the digital notary.
 * @param {String} testDirectory An optional location of the test directory to be used for local
 * configuration storage. If not specified, the location of the configuration is in '~/.bali/'.
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.api = function(account, testDirectory, debug) {

    // validate the parameters
    debug = debug || false;
    if (!account || !account.getTypeId || account.getTypeId() !== bali.types.TAG) {
        const exception = bali.exception({
            $module: '$DigitalNotary',
            $function: '$privateAPI',
            $exception: '$invalidParameter',
            $parameter: account ? bali.text(account.toString()) : bali.NONE,
            $text: bali.text('The account tag format is invalid.')
        });
        if (debug) console.error(exception.toString());
        throw exception;
    }
    if (testDirectory && typeof testDirectory !== 'string') {
        const exception = bali.exception({
            $module: '$DigitalNotary',
            $function: '$privateAPI',
            $exception: '$invalidParameter',
            $account: account,
            $testMode: testDirectory ? true : false,
            $parameter: bali.text(testDirectory.toString()),
            $text: bali.text('The test directory string is invalid.')
        });
        if (debug) console.error(exception.toString());
        throw exception;
    }

    // setup the public and private API implementations
    var publicAPI;
    var privateAPI;
    if (testDirectory) {
        // use a test software security module (SSM)
        publicAPI = preferredProtocol.SSM.publicAPI(debug);
        privateAPI = preferredProtocol.SSM.privateAPI(account, testDirectory, debug);
    } else {
        // or, use a proxy to a hardware security module (HSM)
        publicAPI = preferredProtocol.HSM.publicAPI(debug);
        privateAPI = preferredProtocol.HSM.privateAPI(account, debug);
    }

    // return a singleton object for the API
    return {

        /**
         * This function returns a string providing attributes about this software security module.
         *
         * @returns {String} A string providing attributes about this software security module.
         */
        toString: function() {
            return privateAPI.toString();
        },

        /**
         * This function returns the unique tag for the account that is associated with this
         * digital notary.
         * 
         * @returns {Tag} The unique tag for the account that is associated with this digital
         * notary.
         */
        getAccount: function() {
            return account;
        },

        /**
         * This function returns a list of the protocol versions supported by this digital notary
         * API.
         * 
         * @returns {List} A list of the protocol versions supported by this digital notary API.
         */
        getProtocols: function() {
            return getProtocols(debug);
        },

        /**
         * This function initializes the API.
         */
        initializeAPI: async function() {
            await privateAPI.initializeAPI();
            this.initializeAPI = undefined;  // can only be called once
        },

        /**
         * This function returns the notary certificate associated with this notary key.
         *
         * @returns {Catalog} The notary certificate associated with this notary key.
         */
        getCertificate: async function() {
            return await privateAPI.getCertificate();
        },

        /**
         * This function returns a citation referencing the notary certificate associated
         * with this notary key.
         *
         * @returns {Catalog} A citation referencing the notary certificate associated
         * with this notary key.
         */
        getCitation: async function() {
            return await privateAPI.getCitation();
        },

        /**
         * This function generates a new public-private key pair and uses the private key as the
         * new notary key. It returns the new public notary certificate. Note, during regeneration
         * the old private key is used to sign the new certificate before it is destroyed.
         *
         * @returns {Catalog} The new notary certificate.
         */
        generateKey: async function() {
            return await privateAPI.generateKey();
        },

        /**
         * This function causes the digital notary to forget all information
         * it knows about the current public-private key pair.
         */
        forgetKey: async function() {
            return await privateAPI.forgetKey();
        },

        /**
         * This function generates a document citation for the specified document.
         *
         * @param {Catalog} document The document to be cited.
         * @returns {Catalog} A document citation for the document.
         */
        citeDocument: async function(document) {
            return await publicAPI.citeDocument(document);
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
        citationMatches: async function(citation, document) {
            const api = getPublicAPI(debug, '$citationMatches', citation);
            return await api.citationMatches(citation, document);
        },

        /**
         * This function digitally notarizes the specified document using the private notary
         * key maintained inside the software security module. An optional document citation
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
        notarizeDocument: async function(document, previous, permissions) {
            return await privateAPI.notarizeDocument(document, previous, permissions);
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
        documentIsValid: async function(document, certificate) {
            const api = getPublicAPI(debug, '$documentIsValid', certificate);
            return await api.documentIsValid(document, certificate);
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
        encryptDocument: async function(document, certificate) {
            const api = getPublicAPI(debug, '$encryptDocument', certificate);
            return await api.encryptDocument(document, certificate);
        },

        /**
         * This function uses the notary key to decrypt the specified authenticated
         * encrypted message (AEM). The result is the decrypted document.
         *
         * @param {Catalog} aem The authenticated encrypted message to be decrypted.
         * @returns {Component} The decrypted document.
         */
        decryptDocument: async function(aem) {
            return await privateAPI.decryptDocument(aem);
        }

    };
};


// PRIVATE FUNCTIONS

/**
 * This function returns a list of the protocol versions supported by this digital notary
 * API.
 * 
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @returns {List} A list of the protocol versions supported by this digital notary API.
 */
const getProtocols = function(debug) {
    try {
        return bali.list(Object.keys(protocols));
    } catch (cause) {
        const exception = bali.exception({
            $module: '$DigitalNotary',
            $function: '$getProtocols',
            $exception: '$unexpected',
            $text: bali.text('An unexpected error occurred while attempting to retrieve the protocols for the notary API.')
        }, cause);
        if (debug) console.error(exception.toString());
        throw exception;
    }
};


/**
 * This function returns a reference to the public API that implements the version of
 * the protocol required by the specified document.  If the required version is not
 * supported by this digital notary then an exception is thrown.
 * 
 * @param {Boolean} debug An optional flag that determines whether or not exceptions
 * will be logged to the error console.
 * @param {String} functionName The name of the function making the request.
 * @param {Catalog} document The document being analyzed.
 * @returns {Object} An object that supports the required version of the API.
 */
const getPublicAPI = function(debug, functionName, document) {
    const protocol = document.getValue('$protocol');
    const publicAPI = protocols[protocol.toString()].SSM.publicAPI(debug);
    if (!publicAPI) {
        const exception = bali.exception({
            $module: '$DigitalNotary',
            $function: functionName,
            $exception: '$unsupportedProtocol',
            $expected: Object.keys(protocols),
            $actual: protocol,
            $text: bali.text('Attempted to use an unsupported version of the notary protocol.')
        });
        throw exception;
    }
    return publicAPI;
};

