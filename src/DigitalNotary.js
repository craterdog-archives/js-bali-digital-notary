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
 * This module uses the singleton pattern to provide an object that implements a
 * digital notary interface that is used for account identity and document notarization
 * purposes within the Bali Nebula™. If a test directory is specified, it will be
 * created and used as the location of the local key store. Otherwise, a proxy
 * to a hardware security module will be used for all private key operations.
 */
const bali = require('bali-component-framework');
const v1 = require('./v1');
//const v2 = require('./v2');
//const v3 = require('./v3');
//  ...
const debug = false;  // set to true for error logging

// configure the supported protocol public APIs
const supportedAPIs = {
    v1: v1
//  v2: v2,
//  v3: v3,
//  ...
};
const supportedProtocols = bali.list(Object.keys(supportedAPIs));
const preferredProtocol = supportedAPIs[supportedProtocols.getItem(-1).toString()];  // last is preferred
const publicAPI = preferredProtocol.Public;

// This private constant sets the POSIX end of line character
const EOL = '\n';


/**
 * This function returns an object that implements the API for a digital notary.
 * 
 * @param {Tag} account The unique account tag for the owner of the digital notary.
 * @param {String} testDirectory An optional location of the test directory to be used for local
 * configuration storage. If not specified, the location of the configuration is in '~/.bali/'.
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.api = function(account, testDirectory) {

    // validate the parameters
    if (!account || !account.getTypeId || account.getTypeId() !== bali.types.TAG) {
        const exception = bali.exception({
            $module: '$DigitalNotary',
            $function: '$api',
            $exception: '$invalidParameter',
            $parameter: account ? bali.text(account.toString()) : bali.NONE,
            $message: bali.text('The account tag is invalid.')
        });
        if (debug) console.error(exception.toString());
        throw exception;
    }
    if (testDirectory && typeof testDirectory !== 'string') {
        const exception = bali.exception({
            $module: '$DigitalNotary',
            $function: '$api',
            $exception: '$invalidParameter',
            $account: account,
            $testMode: testDirectory ? true : false,
            $parameter: bali.text(testDirectory.toString()),
            $message: bali.text('The test directory string is invalid.')
        });
        throw exception;
    }

    var privateAPI;

    return {

        initializeAPI: async function() {
            try {
                // connect to the private hardware security module for the account
                if (testDirectory) {
                    // use a test software security module (SSM)
                    privateAPI = preferredProtocol.Test.api(account, testDirectory);
                } else {
                    // or, use a proxy to a hardware security module (HSM)
                    privateAPI = preferredProtocol.Proxy.api(account);
                }
                await privateAPI.initialize();
                this.initializeAPI = function() {
                    const exception = bali.exception({
                        $module: '$DigitalNotary',
                        $function: '$initializeAPI',
                        $exception: '$alreadyInitialized',
                        $account: account,
                        $testMode: testDirectory ? true : false,
                        $message: bali.text('The Bali Digital Notary API™ has already been initialized.')
                    });
                    throw exception;
                };
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$initializeAPI',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $message: bali.text('An unexpected error occurred while attempting to initialize the API.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        getAccount: function() {
            return account;
        },

        supportedProtocols: async function() {
            return supportedProtocols;
        },

        /**
         * This function (re)generates a private notary key and its associated public notary
         * certificate. The private notary key is generated on the hardware security module
         * and remains there. The associated public notary certificate is returned and a
         * document citation for the certificate is stored in the local configuration
         * directory.
         * 
         * @returns {Catalog} A new Bali Notarized Document™ containing the public
         * notary certificate associated with the new private notary key.
         */
        generateKeyPair: async function() {
            try {
                var notaryCertificate = await privateAPI.generate();
                return notaryCertificate;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$generateKeyPair',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $message: bali.text('An unexpected error occurred while attempting to (re)generate a new key pair.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function returns a document citation referencing the Bali Notarized Document™
         * containing the public certificate for this digital notary.
         * 
         * @returns {Catalog} A document citation referencing the document containing the
         * public certificate for this digital notary.
         */
        getCitation: async function() {
            try {
                return await privateAPI.citation();
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$getCitation',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $message: bali.text('An unexpected error occurred while attempting to retrieve the notary certificate citation.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function returns a Bali Notarized Document™ containing the public certificate for
         * this digital notary.
         * 
         * @returns {Catalog} The notarized document containing the public certificate
         * for this digital notary.
         */
        getCertificate: async function() {
            try {
                return await privateAPI.certificate();
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$getCertificate',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $message: bali.text('An unexpected error occurred while attempting to retrieve the notary certificate.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function digitally notarizes the specified document using the private notary
         * key maintained inside the hardware security module. The specified document citation
         * is updated with the digest of the notarized document. The newly notarized document
         * is returned.
         * 
         * @param {Component} component The document content to be notarized.
         * @param {Catalog} previous An optional document citation to the previous version of
         * the notarized document.
         * @returns {Catalog} A catalog that is the newly notarized document for the component.
         */
        notarizeDocument: async function(component, previous) {
            // validate the parameters
            if (!component || !component.getTypeId) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$notarizeDocument',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: component ? bali.text(component.toString()) : bali.NONE,
                    $message: bali.text('The previous document citation is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }
            if (previous && (!previous.getTypeId || previous.getTypeId() !== bali.types.CATALOG)) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$notarizeDocument',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: bali.text(previous.toString()),
                    $message: bali.text('The previous document citation is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }

            try {
                // retrieve the notary certificate citation
                const citation = await privateAPI.citation();
                if (!citation) {
                    const exception = bali.exception({
                        $module: '$DigitalNotary',
                        $function: '$notarizeDocument',
                        $exception: '$missingKey',
                        $account: account,
                        $testMode: testDirectory ? true : false,
                        $message: bali.text('The notary key is missing.')
                    });
                    throw exception;
                }

                // set the component parameters if necessary
                if (!component.isParameterized()) {
                    const parameters = bali.parameters({
                        $tag: bali.tag(),
                        $version: bali.version()
                    });
                    // TODO: need to find a way not to require a setParameters() method
                    component.setParameters(parameters);
                }

                // construct the notarized document
                const document = bali.catalog();
                document.setValue('$protocol', publicAPI.protocol);
                document.setValue('$timestamp', bali.moment());  // now
                if (previous) document.setValue('$previous', previous);
                document.setValue('$component', component);
                if (citation) document.setValue('$citation', citation);
                const signature = await privateAPI.sign(document);
                document.setValue('$signature', signature);

                return document;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$notarizeDocument',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $component: component,
                    $previous: previous,
                    $document: document,
                    $message: bali.text('An unexpected error occurred while attempting to notarize a document.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function generates a document citation for the specified document.
         * 
         * @param {Catalog} document The document to be cited.
         * @returns {Catalog} A document citation for the document.
         */
        citeDocument: async function(document) {
            // validate the parameters
            if (!document || !document.getTypeId || document.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citeDocument',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: document ? bali.text(document.toString()) : bali.NONE,
                    $message: bali.text('The previous document citation is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }

            // verify the document parameters
            const parameters = document.getValue('$component').getParameters();
            if (!parameters || !parameters.getParameter('$tag') || !parameters.getParameter('$version')) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citeDocument',
                    $exception: '$missingParameters',
                    $document: document,
                    $message: bali.text('The document parameters are missing.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }

            try {
                const tag = parameters.getParameter('$tag');
                const version = parameters.getParameter('$version');
                const digest = publicAPI.digest(document);
                const citation = publicAPI.citation(tag, version, digest);
                return citation;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citeDocument',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $document: document,
                    $message: bali.text('An unexpected error occurred while attempting to cite a document.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function determines whether or not the specified document citation matches
         * the specified document. The citation only matches if its digest matches the
         * digest of the document.
         * 
         * @param {Catalog} citation A document citation allegedly referring to the
         * specified document.
         * @param {Catalog} document The document to be tested.
         * @returns {Boolean} Whether or not the citation matches the specified document.
         */
        citationMatches: async function(citation, document) {
            // validate the parameters
            if (!citation || !citation.getTypeId || citation.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citationMatches',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: citation ? bali.text(citation.toString()) : bali.NONE,
                    $message: bali.text('The document citation is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }
            if (!document || !document.getTypeId || document.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citationMatches',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: document ? bali.text(document.toString()) : bali.NONE,
                    $message: bali.text('The document is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }

            try {
                // verify the citation
                const publicAPI = getPublicAPI('$citationMatches', citation);
                var digest = publicAPI.digest(document);

                return digest.isEqualTo(citation.getValue('$digest'));

            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$citationMatches',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $document: document,
                    $citation: citation,
                    $message: bali.text('An unexpected error occurred while attempting to verify a document citation.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function determines whether or not the notary seal on the specified document
         * is valid.
         * 
         * @param {Catalog} document The notarized document to be tested.
         * @param {Catalog} certificate A catalog containing the public notary key for the
         * private notary key that allegedly notarized the specified document.
         * @returns {Boolean} Whether or not the notary seal on the document is valid.
         */
        documentIsValid: async function(document, certificate) {
            // validate the parameters
            if (!document || !document.getTypeId || document.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$documentIsValid',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: document ? bali.text(document.toString()) : bali.NONE,
                    $message: bali.text('The document is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }
            if (!certificate || !certificate.getTypeId || certificate.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$documentIsValid',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: certificate ? bali.text(certificate.toString()) : bali.NONE,
                    $message: bali.text('The certificate is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }

            try {
                const publicAPI = getPublicAPI('$documentIsValid', certificate);
                const catalog = bali.catalog.extraction(document, bali.list([
                    '$protocol',
                    '$timestamp',
                    '$previous',
                    '$component',
                    '$citation'
                ]));  // everything but the signature
                const publicKey = certificate.getValue('$publicKey');
                const signature = document.getValue('$signature');
                const isValid = publicAPI.verify(catalog, publicKey, signature);
                return isValid;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$documentIsValid',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $document: document,
                    $certificate: certificate,
                    $message: bali.text('An unexpected error occurred while attempting to verify a notarized document.')
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
         * @param {Catalog} certificate A catalog containing the public notary key for the
         * intended recipient of the encrypted component.
         * @returns {Catalog} An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes for the encrypted component.
         */
        encryptComponent: async function(component, certificate) {
            // validate the parameters
            if (!component || !component.getTypeId) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$encryptComponent',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: component ? bali.text(component.toString()) : bali.NONE,
                    $message: bali.text('The component is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }
            if (!certificate || !certificate.getTypeId || certificate.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$encryptComponent',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: certificate ? bali.text(certificate.toString()) : bali.NONE,
                    $message: bali.text('The certificate is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }

            try {
                const publicAPI = getPublicAPI('$encryptComponent', certificate);
                const publicKey = certificate.getValue('$publicKey');
                const aem = publicAPI.encrypt(component, publicKey);
                return aem;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$encryptComponent',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $certificate: certificate,
                    $message: bali.text('An unexpected error occurred while attempting to encrypt a component.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        },

        /**
         * This function uses the private notary key in the hardware security module to decrypt
         * the ciphertext residing in the specified authenticated encrypted message (AEM). THe
         * result is the decrypted component.
         * 
         * @param {Catalog} aem An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes required to decrypt the component.
         * @returns {Component} The decrypted component.
         */
        decryptComponent: async function(aem) {
            // validate the parameters
            if (!aem || !aem.getTypeId || aem.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$decryptComponent',
                    $exception: '$invalidParameter',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $parameter: aem ? bali.text(aem.toString()) : bali.NONE,
                    $message: bali.text('The authenticated encrypted message is invalid.')
                });
                if (debug) console.error(exception.toString());
                throw exception;
            }

            try {
                const citation = await privateAPI.citation();
                if (!citation) {
                    const exception = bali.exception({
                        $module: '$DigitalNotary',
                        $function: '$decryptComponent',
                        $exception: '$missingKey',
                        $account: account,
                        $message: bali.text('The notary key is missing.')
                    });
                    if (debug) console.error(exception.toString());
                    throw exception;
                }
                const protocol = aem.getValue('$protocol');
                if (!publicAPI.protocol.isEqualTo(protocol)) {
                    const exception = bali.exception({
                        $module: '$DigitalNotary',
                        $function: '$decryptComponent',
                        $exception: '$unsupportedProtocol',
                        $expected: publicAPI.protocol,
                        $actual: protocol,
                        $message: bali.text('The component was encrypted using an unsupported version of the notary protocol.')
                    });
                    if (debug) console.error(exception.toString());
                    throw exception;
                }
                const component = await privateAPI.decrypt(aem);
                return component;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$decryptComponent',
                    $exception: '$unexpected',
                    $account: account,
                    $testMode: testDirectory ? true : false,
                    $aem: aem,
                    $message: bali.text('An unexpected error occurred while attempting to decrypt an authenticated encrypted message.')
                }, cause);
                if (debug) console.error(exception.toString());
                throw exception;
            }
        }

    };
};


// PRIVATE FUNCTIONS

/*
 * This function returns the requested version of the public API or throws an exception
 * if it does not exist.
 */
const getPublicAPI = function(functionName, document) {
    const protocol = document.getValue('$protocol');
    const publicAPI = supportedAPIs[protocol.toString()].Public;
    if (!publicAPI) {
        const exception = bali.exception({
            $module: '$DigitalNotary',
            $function: functionName,
            $exception: '$unsupportedProtocol',
            $expected: supportedProtocols,
            $actual: protocol,
            $message: bali.text('Attempted to use an unsupported version of the notary protocol.')
        });
        throw exception;
    }
    return publicAPI;
};
