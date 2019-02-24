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
const fs = require('fs');
const os = require('os');
const bali = require('bali-component-framework');
const v1 = require('./v1');
//const v2 = require('./v2');
//const v3 = require('./v3');
//  ...

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
 * @param {String} testDirectory The location of the test directory to be used for local
 * configuration storage. If not specified, the location of the configuration is in '~/.bali/'.
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.api = function(testDirectory) {

    const configDirectory = testDirectory || os.homedir() + '/.bali/';
    const configFilename = 'Citation.bali';
    const notaryCitation = retrieveConfiguration(configDirectory, configFilename);
    const notaryTag = notaryCitation.getValue('$tag');
    const privateAPI = connectToHSM(testDirectory);

    return {

        supportedProtocols: function() {
            return supportedProtocols;
        },

        /**
         * This method (re)generates a private notary key and its associated public notary
         * certificate. The private notary key is generated on the hardware security module
         * and remains there. The associated public notary certificate is returned and a
         * document citation for the certificate is stored in the local configuration
         * directory.
         * 
         * @returns {Catalog} A new Bali Notarized Document™ containing the public
         * notary certificate associated with the new private notary key.
         */
        generateKeys: function() {
            var notaryCertificate = privateAPI.generate();
            var certificateCitation = privateAPI.citation();
            storeConfiguration(configDirectory, configFilename, certificateCitation);
            return notaryCertificate;
        },

        /**
         * This method returns a document citation referencing the Bali Notarized Document™
         * containing the public certificate for this digital notary.
         * 
         * @returns {Catalog} A document citation referencing the document containing the
         * public certificate for this digital notary.
         */
        getCitation: function() {
            return privateAPI.citation();
        },

        /**
         * This method returns a Bali Notarized Document™ containing the public certificate for
         * this digital notary.
         * 
         * @returns {Catalog} The notarized document containing the public certificate
         * for this digital notary.
         */
        getCertificate: function() {
            return privateAPI.certificate();
        },

        /**
         * This method digitally notarizes the specified document using the private notary
         * key maintained inside the hardware security module. The specified document citation
         * is updated with the digest of the notarized document. The newly notarized document
         * is returned.
         * 
         * @param {Component} component The document content to be notarized.
         * @param {Catalog} previous An optional document citation to the previous version of
         * the notarized document.
         * @returns {Catalog} A catalog that is the newly notarized document for the component.
         */
        notarizeDocument: function(component, previous) {

            // extract component parameters
            var parameters = component.getParameters();
            if (!parameters) {
                parameters = bali.parameters({
                    $tag: bali.tag(),
                    $version: bali.version()
                });
                // TODO: need to find a way not to require a setParameters() method
                component.setParameters(parameters);
            }

            // retrieve the notary certificate citation
            const citation = privateAPI.citation();
            if (!citation) {
                throw bali.exception({
                    $module: '$DigitalNotary',
                    $procedure: '$notarizeDocument',
                    $exception: '$missingKey',
                    $tag: notaryTag,
                    $message: '"The notary key is missing."'
                });
            }

            // construct the notarized document
            const document = bali.catalog();
            document.setValue('$protocol', publicAPI.protocol);
            document.setValue('$timestamp', bali.moment());  // now
            if (previous) document.setValue('$previous', previous);
            document.setValue('$component', component);
            document.setValue('$citation', citation);
            document.setValue('$signature', privateAPI.sign(document));

            return document;
        },

        /**
         * This method generates a document citation for the specified document.
         * 
         * @param {Catalog} document The document to be cited.
         * @returns {Catalog} A document citation for the document.
         */
        citeDocument: function(document) {
            const parameters = document.getValue('$component').getParameters();
            if (!parameters) {
                throw bali.exception({
                    $module: '$DigitalNotary',
                    $procedure: '$citeDocument',
                    $exception: '$missingParameters',
                    $document: document,
                    $message: '"The document parameters are missing."'
                });
            }
            const tag = parameters.getParameter('$tag');
            const version = parameters.getParameter('$version');
            const digest = publicAPI.digest(document);
            const citation = publicAPI.citation(tag, version, digest);
            return citation;
        },

        /**
         * This method determines whether or not the specified document citation matches
         * the specified document. The citation only matches if its digest matches the
         * digest of the document.
         * 
         * @param {Catalog} document The document to be tested.
         * @param {Catalog} citation A document citation allegedly referring to the
         * specified document.
         * @returns {Boolean} Whether or not the citation matches the specified document.
         */
        documentMatches: function(document, citation) {
            const publicAPI = getPublicAPI('$documentMatches', citation);
            var digest = publicAPI.digest(document);
            return digest.isEqualTo(citation.getValue('$digest'));
        },

        /**
         * This method determines whether or not the notary seal on the specified document
         * is valid.
         * 
         * @param {Catalog} document The notarized document to be tested.
         * @param {Catalog} certificate A catalog containing the public notary key for the
         * private notary key that allegedly notarized the specified document.
         * @returns {Boolean} Whether or not the notary seal on the document is valid.
         */
        documentIsValid: function(document, certificate) {
            const publicAPI = getPublicAPI('$documentIsValid', certificate);
            const catalog = bali.catalog();
            const previous = document.getValue('$previous');
            catalog.setValue('$protocol', document.getValue('$protocol'));
            catalog.setValue('$timestamp', document.getValue('$timestamp'));
            if (previous) catalog.setValue('$previous', previous);
            catalog.setValue('$component', document.getValue('$component'));
            catalog.setValue('$citation', document.getValue('$citation'));
            const publicKey = certificate.getValue('$publicKey');
            const signature = document.getValue('$signature');
            const isValid = publicAPI.verify(catalog, publicKey, signature);
            return isValid;
        },

        /**
         * This method uses the specified public notary certificate to encrypt the specified
         * message in such a way that only the intended recipient of the encrypted message can
         * decrypt it using their private notary key. The result is an authenticated encrypted
         * message (AEM) containing the ciphertext and other required attributes needed to
         * decrypt the message.
         * 
         * @param {Component} message The message component to be encrypted using the specified
         * public notary certificate.
         * @param {Catalog} certificate A catalog containing the public notary key for the
         * intended recipient of the encrypted message.
         * @returns {Catalog} An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes for the specified message.
         */
        encryptMessage: function(message, certificate) {
            const publicAPI = getPublicAPI('$encryptMessage', certificate);
            var publicKey = certificate.getValue('$publicKey');
            var aem = publicAPI.encrypt(message, publicKey);
            return aem;
        },

        /**
         * This method uses the private notary key in the hardware security module to decrypt
         * the ciphertext residing in the specified authenticated encrypted message (AEM). THe
         * result is the decrypted message component.
         * 
         * @param {Catalog} aem An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes required to decrypt the message.
         * @returns {Component} The decrypted message component.
         */
        decryptMessage: function(aem) {
            if (!privateAPI.citation()) {
                throw bali.exception({
                    $module: '$DigitalNotary',
                    $procedure: '$decryptMessage',
                    $exception: '$missingKey',
                    $tag: notaryTag,
                    $message: '"The notary key is missing."'
                });
            }
            const protocol = aem.getValue('$protocol');
            if (!publicAPI.protocol.isEqualTo(protocol)) {
                throw bali.exception({
                    $module: '$DigitalNotary',
                    $procedure: '$decryptMessage',
                    $exception: '$unsupportedProtocol',
                    $expected: publicAPI.protocol,
                    $actual: protocol,
                    $message: '"The message was encrypted using an unsupported version of the notary protocol."'
                });
            }
            var message = bali.parse(privateAPI.decrypt(aem));
            return message;
        }

    };
};


// PRIVATE FUNCTIONS

/*
 * This function stores the digital notary configuration citation in the specified
 * configuration directory and filename.
 */
const storeConfiguration = function(configDirectory, configFilename, citation) {
    try {
        const configFile = configDirectory + configFilename;
        const source = citation.toString() + EOL;  // add POSIX compliant end of line
        fs.writeFileSync(configFile, source, {encoding: 'utf8', mode: 384});  // -rw------- permissions
    } catch (e) {
        throw bali.exception({
            $module: '$DigitalNotary',
            $procedure: '$generateKeys',
            $exception: '$configurationAccess',
            $directory: '"' + configDirectory + '"',
            $filename: '"' + configFilename + '"',
            $message: '"' + EOL + 'Unable to store the configuration file: ' + EOL + e + EOL + '"'
        });
    }
};

/*
 * This function loads the digital notary configuration citation from the specified
 * configuration directory and filename.
 */
const retrieveConfiguration = function(configDirectory, configFilename) {
    try {
        // create the config directory if necessary
        if (!fs.existsSync(configDirectory)) fs.mkdirSync(configDirectory, 448);  // drwx------ permissions

        // load the account citation
        const configFile = configDirectory + configFilename;
        var source;
        var certificateCitation;
        if (fs.existsSync(configFile)) {
            source = fs.readFileSync(configFile, 'utf8');
            certificateCitation = bali.parse(source);
        } else {
            certificateCitation = publicAPI.citation();
            source = certificateCitation.toString() + EOL;  // add POSIX compliant end of line
            fs.writeFileSync(configFile, source, {encoding: 'utf8', mode: 384});  // -rw------- permissions
        }
        return certificateCitation;
    } catch (e) {
        throw bali.exception({
            $module: '$DigitalNotary',
            $procedure: '$api',
            $exception: '$configurationAccess',
            $directory: '"' + configDirectory + '"',
            $filename: '"' + configFilename + '"',
            $message: '"' + EOL + 'Unable to retrieve the current configuration file, or create a new one: ' + EOL + e + EOL + '"'
        });
    }
};

/*
 * This function returns the requested version of the public API or throws an exception
 * if it does not exist.
 */
const getPublicAPI = function(procedure, document) {
    const protocol = document.getValue('$protocol');
    const publicAPI = supportedAPIs[protocol.toString()].Public;
    if (!publicAPI) {
        throw bali.exception({
            $module: '$DigitalNotary',
            $procedure: procedure,
            $exception: '$unsupportedProtocol',
            $expected: supportedProtocols,
            $actual: protocol,
            $message: '"Attempted to use an unsupported version of the notary protocol."'
        });
    }
    return publicAPI;
};

/*
 * This function connects to a remote hardware security module which implements all API
 * methods that utilize the private key.
 */
const connectToHSM = function(testDirectory) {
    try {
        // connect to the private hardware security module for the account
        const privateAPI = testDirectory ? 
            // use a test software security module (SSM)
            preferredProtocol.Test.api(testDirectory) :
            // or, use a proxy to a hardware security module (HSM)
            preferredProtocol.Proxy.api();
        return privateAPI;
    } catch (e) {
        throw bali.exception({
            $module: '$DigitalNotary',
            $procedure: '$api',
            $exception: '$hsmAccess',
            $testMode: testDirectory ? true : false,
            $message: '"' + EOL + 'Unable to access the hardware security module (HSM): ' + EOL + e + EOL + '"'
        });
    }
};
