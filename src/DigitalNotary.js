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
 * This module uses the singleton pattern to expose two objects each implementing
 * digital notary APIs that are used for component notarization purposes within
 * the Bali Nebula™. The first is a public API that can used by anyone to validate
 * existing notarized documents. The second is a private API that uses a public-private
 * key pair to provide full digital signing capabilities associated with a specific
 * user account.
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
    debug = debug || false;

    // setup the public API implementation
    const publicAPI = preferredProtocol.SSM.publicAPI();

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
            try {
                return bali.list(Object.keys(protocols));
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$getProtocols',
                    $exception: '$unexpected',
                    $text: bali.text('An unexpected error occurred while attempting to retrieve the supported security protocols.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },
   
        /**
         * This function generates a document citation for the specified notarized document.
         *
         * @param {Catalog} document The document to be cited.
         * @returns {Catalog} A document citation for the notarized document.
         */
        citeDocument: function(document) {
            try {
                validateParameter('$citeDocument', document, 'document');
                return publicAPI.citeDocument(document);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citeDocument',
                    $exception: '$unexpected',
                    $document: document,
                    $text: bali.text('An unexpected error occurred while attempting to cite a notarized document.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },
   
        /**
         * This function determines whether or not the specified document citation matches
         * the specified notarized document. The citation only matches if its digest matches
         * the digest of the notarized document exactly.
         *
         * @param {Catalog} citation A document citation allegedly referring to the
         * specified notarized document.
         * @param {Catalog} document The notarized document to be tested.
         * @returns {Boolean} Whether or not the citation matches the specified notarized document.
         */
        citationMatches: function(citation, document) {
            try {
                validateParameter('$citationMatches', citation, 'citation');
                validateParameter('$citationMatches', document, 'document');
                const api = getPublicAPI('$citationMatches', citation);
                return api.citationMatches(citation, document);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citationMatches',
                    $exception: '$unexpected',
                    $citation: citation,
                    $document: document,
                    $text: bali.text('An unexpected error occurred while attempting to match a citation to a notarized document.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },
   
        /**
         * This function determines whether or not the notary seal on the specified notarized
         * document is valid.
         *
         * @param {Catalog} document The notarized document to be tested.
         * @param {Catalog} certificate A catalog containing the public certificate for the
         * private notary key that allegedly notarized the specified notarized document.
         * @returns {Boolean} Whether or not the notary seal on the notarized document is valid.
         */
        documentIsValid: function(document, certificate) {
            try {
                validateParameter('$documentIsValid', document, 'document');
                validateParameter('$documentIsValid', certificate, 'certificate');
                const api = getPublicAPI('$documentIsValid', certificate);
                return api.documentIsValid(document, certificate);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$documentIsValid',
                    $exception: '$unexpected',
                    $document: document,
                    $certificate: certificate,
                    $text: bali.text('An unexpected error occurred while attempting to validate a notarized document.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },
   
        /**
         * This function uses the specified public notary certificate to encrypt the specified
         * component in such a way that only the intended recipient of the encrypted component can
         * decrypt it using their private notary key. The result is an authenticated encrypted
         * message (AEM) containing the ciphertext and other required attributes needed to
         * decrypt the message.
         *
         * @param {Component} component The component to be encrypted using the specified
         * public notary certificate.
         * @param {Catalog} certificate A catalog containing the public certificate for the
         * intended recipient of the encrypted component.
         * @returns {Catalog} An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes for the encrypted component.
         */
        encryptComponent: function(component, certificate) {
            try {
                validateParameter('$encryptComponent', component, 'component');
                validateParameter('$encryptComponent', certificate, 'certificate');
                const api = getPublicAPI('$encryptComponent', certificate);
                return api.encryptComponent(component, certificate);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$encryptComponent',
                    $exception: '$unexpected',
                    $component: component,
                    $certificate: certificate,
                    $text: bali.text('An unexpected error occurred while attempting to encrypt a component.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
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
    validateParameter('$api', account, 'tag');
    validateParameter('$api', testDirectory, 'directory');
    debug = debug || false;

    // setup the public and private API implementations
    var publicAPI;
    var privateAPI;
    if (testDirectory) {
        // use a test software security module (SSM)
        publicAPI = preferredProtocol.SSM.publicAPI();
        privateAPI = preferredProtocol.SSM.privateAPI(account, testDirectory);
    } else {
        // or, use a proxy to a hardware security module (HSM)
        publicAPI = preferredProtocol.HSM.publicAPI();
        privateAPI = preferredProtocol.HSM.privateAPI(account);
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
        getProtocols: async function() {
            try {
                return bali.list(Object.keys(protocols));
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$getProtocols',
                    $exception: '$unexpected',
                    $text: bali.text('An unexpected error occurred while attempting to retrieve the supported security protocols.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function returns the notary certificate associated with this notary key.
         *
         * @returns {Catalog} The notary certificate associated with this notary key.
         */
        getCertificate: async function() {
            try {
                return await privateAPI.getCertificate();
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$getCertificate',
                    $exception: '$unexpected',
                    $text: bali.text('An unexpected error occurred while attempting to retrieve the notary certificate.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function returns a citation referencing the notary certificate associated
         * with this notary key.
         *
         * @returns {Catalog} A citation referencing the notary certificate associated
         * with this notary key.
         */
        getCitation: async function() {
            try {
                return await privateAPI.getCitation();
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$getCitation',
                    $exception: '$unexpected',
                    $text: bali.text('An unexpected error occurred while attempting to retrieve the citation to the notary certificate.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function generates a new public-private key pair and uses the private key as the
         * new notary key. It returns the new public notary certificate. Note, during regeneration
         * the old private key is used to sign the new certificate before it is destroyed.
         *
         * @returns {Catalog} The new notary certificate.
         */
        generateKey: async function() {
            try {
                return await privateAPI.generateKey();
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$generateKey',
                    $exception: '$unexpected',
                    $text: bali.text('An unexpected error occurred while attempting to (re)generate the notary key.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function causes the digital notary to forget all information
         * it knows about the current public-private key pair.
         */
        forgetKey: async function() {
            try {
                return await privateAPI.forgetKey();
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$forgetKey',
                    $exception: '$unexpected',
                    $text: bali.text('An unexpected error occurred while attempting to forget the notary key.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function generates a document citation for the specified notarized document.
         *
         * @param {Catalog} document The notarized document to be cited.
         * @returns {Catalog} A document citation for the notarized document.
         */
        citeDocument: async function(document) {
            try {
                validateParameter('$citeDocument', document, 'document');
                return await publicAPI.citeDocument(document);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citeDocument',
                    $exception: '$unexpected',
                    $document: document,
                    $text: bali.text('An unexpected error occurred while attempting to cite a notarized document.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function determines whether or not the specified document citation matches
         * the specified notarized document. The citation only matches if its digest matches
         * the digest of the notarized document exactly.
         *
         * @param {Catalog} citation A document citation allegedly referring to the
         * specified notarized document.
         * @param {Catalog} document The notarized document to be tested.
         * @returns {Boolean} Whether or not the citation matches the specified notarized document.
         */
        citationMatches: async function(citation, document) {
            try {
                validateParameter('$citationMatches', citation, 'citation');
                validateParameter('$citationMatches', document, 'document');
                const api = getPublicAPI('$citationMatches', citation);
                return await api.citationMatches(citation, document);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citationMatches',
                    $exception: '$unexpected',
                    $citation: citation,
                    $document: document,
                    $text: bali.text('An unexpected error occurred while attempting to match a citation to a notarized document.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function digitally signs the specified component using the private notary
         * key maintained by the software security module. The component must be parameterized
         * with the following parameters:
         * <pre>
         *  * $tag - a unique identifier for the component
         *  * $version - the version of the component
         *  * $permissions - a citation to a notarized document containing the permissions defining
         *                   who can access the component
         *  * $previous - a citation to the previous version of the component (or bali.NONE)
         * </pre>
         * 
         * The newly notarized component is returned.
         *
         * @param {Component} component The component to be notarized.
         * @returns {Catalog} The newly notarized component.
         */
        signComponent: async function(component) {
            try {
                validateParameter('$signComponent', component, 'component');
                return await privateAPI.signComponent(component);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$signComponent',
                    $exception: '$unexpected',
                    $component: component,
                    $text: bali.text('An unexpected error occurred while attempting to notarize a component.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function determines whether or not the notary seal on the specified notarized document
         * is valid.
         *
         * @param {Catalog} document The notarized document to be tested.
         * @param {Catalog} certificate A catalog containing the public certificate for the
         * private notary key that allegedly notarized the specified document.
         * @returns {Boolean} Whether or not the notary seal on the notarized document is valid.
         */
        documentIsValid: async function(document, certificate) {
            try {
                validateParameter('$documentIsValid', document, 'document');
                validateParameter('$documentIsValid', certificate, 'certificate');
                const api = getPublicAPI('$documentIsValid', certificate);
                return await api.documentIsValid(document, certificate);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$documentIsValid',
                    $exception: '$unexpected',
                    $document: document,
                    $certificate: certificate,
                    $text: bali.text('An unexpected error occurred while attempting to validate a notarized document.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function uses the specified public notary certificate to encrypt the specified
         * component in such a way that only the intended recipient of the encrypted component can
         * decrypt it using their private notary key. The result is an authenticated encrypted
         * message (AEM) containing the ciphertext and other required attributes needed to
         * decrypt the message.
         *
         * @param {Component} component The component to be encrypted using the specified
         * public notary certificate.
         * @param {Catalog} certificate A catalog containing the public certificate for the
         * intended recipient of the encrypted component.
         * @returns {Catalog} An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes for the encrypted component.
         */
        encryptComponent: async function(component, certificate) {
            try {
                validateParameter('$encryptComponent', component, 'component');
                validateParameter('$encryptComponent', certificate, 'certificate');
                const api = getPublicAPI('$encryptComponent', certificate);
                return await api.encryptComponent(component, certificate);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$encryptComponent',
                    $exception: '$unexpected',
                    $component: component,
                    $certificate: certificate,
                    $text: bali.text('An unexpected error occurred while attempting to encrypt a component.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function uses the notary key to decrypt the specified authenticated
         * encrypted message (AEM). The result is the decrypted component.
         *
         * @param {Catalog} aem The authenticated encrypted message to be decrypted.
         * @returns {Component} The decrypted component.
         */
        decryptComponent: async function(aem) {
            try {
                validateParameter('$decryptComponent', aem, 'aem');
                return await privateAPI.decryptComponent(aem);
            } catch (cause) {
                const exception = cause.constructor.name === 'Exception' ? cause : bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$decryptComponent',
                    $exception: '$unexpected',
                    $aem: aem,
                    $text: bali.text('An unexpected error occurred while attempting to decrypt a component.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        }

    };
};


// PRIVATE FUNCTIONS

/**
 * This function returns a reference to the public API that implements the version of
 * the protocol required by the specified notarized document.  If the required version
 * is not supported by this digital notary then an exception is thrown.
 * 
 * @param {String} functionName The name of the function making the request.
 * @param {Catalog} document The notarized document being analyzed.
 * @returns {Object} An object that supports the required version of the API.
 */
const getPublicAPI = function(functionName, document) {
    const protocol = document.getValue('$protocol');
    const publicAPI = protocols[protocol.toString()].SSM.publicAPI();
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


const validateParameter = function(functionName, parameter, type) {
    if (parameter) {
        switch (type) {
            case 'binary':
            case 'moment':
            case 'tag':
            case 'version':
                if (parameter.getTypeId && parameter.getTypeId() === bali.types[type.toUpperCase()]) return;
                break;
            case 'directory':
                const pattern = new RegExp('/?(\\w+/)+');
                if (typeof parameter === 'string' && pattern.test(parameter)) return;
                break;
            case 'component':
                if (parameter.getTypeId) return;
                break;
            case 'citation':
                if (parameter.getTypeId && parameter.isEqualTo(bali.NONE)) return;
                if (parameter.getTypeId && parameter.getTypeId() === bali.types.CATALOG && parameter.getSize() === 5) {
                    validateParameter(functionName, parameter.getValue('$protocol'), 'version');
                    validateParameter(functionName, parameter.getValue('$timestamp'), 'moment');
                    validateParameter(functionName, parameter.getValue('$tag'), 'tag');
                    validateParameter(functionName, parameter.getValue('$version'), 'version');
                    validateParameter(functionName, parameter.getValue('$digest'), 'binary');
                    return;
                }
                break;
            case 'certificate':
                if (parameter.getTypeId && parameter.getTypeId() === bali.types.CATALOG && parameter.getSize() === 4) {
                    validateParameter(functionName, parameter.getValue('$protocol'), 'version');
                    validateParameter(functionName, parameter.getValue('$timestamp'), 'moment');
                    validateParameter(functionName, parameter.getValue('$account'), 'tag');
                    validateParameter(functionName, parameter.getValue('$publicKey'), 'binary');
                    return;
                }
                break;
            case 'aem':
                if (parameter.getTypeId && parameter.getTypeId() === bali.types.CATALOG && parameter.getSize() === 6) {
                    validateParameter(functionName, parameter.getValue('$protocol'), 'version');
                    validateParameter(functionName, parameter.getValue('$timestamp'), 'moment');
                    validateParameter(functionName, parameter.getValue('$seed'), 'binary');
                    validateParameter(functionName, parameter.getValue('$iv'), 'binary');
                    validateParameter(functionName, parameter.getValue('$auth'), 'binary');
                    validateParameter(functionName, parameter.getValue('$ciphertext'), 'binary');
                    return;
                }
                break;
            case 'document':
                if (parameter.getTypeId && parameter.getTypeId() === bali.types.CATALOG && parameter.getSize() === 5) {
                    validateParameter(functionName, parameter.getValue('$component'), 'component');
                    validateParameter(functionName, parameter.getValue('$protocol'), 'version');
                    validateParameter(functionName, parameter.getValue('$timestamp'), 'moment');
                    validateParameter(functionName, parameter.getValue('$certificate'), 'citation');
                    validateParameter(functionName, parameter.getValue('$signature'), 'binary');
                    const parameters = parameter.getValue('$component').getParameters();
                    if (!parameters || !parameters.getParameter('$tag') || !parameters.getParameter('$version')) {
                        const exception = bali.exception({
                            $module: '$v1SSM',
                            $function: '$citeDocument',
                            $exception: '$missingParameters',
                            $document: parameter,
                            $text: bali.text('The notarized document identity parameters are missing.')
                        });
                        throw exception;
                    }
                    return;
                }
                break;
        }
    }
    const exception = bali.exception({
        $module: '$DigitalNotary',
        $function: functionName,
        $exception: '$invalidParameter',
        $parameter: parameter ? bali.text(parameter.toString()) : bali.NONE,
        $text: bali.text('An invalid parameter was passed to the function.')
    });
    throw exception;
};
