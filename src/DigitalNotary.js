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
const version = require('./v1');
const publicAPI = version.v1Public;

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
    const privateAPI = connectToHSM(notaryTag, testDirectory);

    return {

        supportedVersions: function() {
            var versions = bali.list([publicAPI.protocol]);
            return versions;
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
         * @param {Component} component The component to be notarized.
         * @param {Catalog} previous A document citation to the previous version of the notarized document.
         * @returns {Object} An object containing the newly notarized document for the component and
         * a document citation to the notarized document.
         */
        notarizeComponent: function(component, previous) {
            // force previous version to 'none' if necessary
            previous = previous || bali.NONE;

            // create the content with the component parameters
            const parameters = component.getParameters() || bali.parameters({});
            parameters.setParameter('$protocol', publicAPI.protocol);
            const tag = parameters.getParameter('$tag') || bali.tag();
            parameters.setParameter('$tag', tag);
            const version = parameters.getParameter('$version') || bali.version();
            parameters.setParameter('$version', version);
            const content = bali.catalog(component, parameters);

            // retrieve the notary certificate
            const certificate = privateAPI.citation();
            if (!certificate) {
                throw bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$notarizeComponent',
                    $exception: '$missingKey',
                    $tag: notaryTag,
                    $message: '"The notary key is missing."'
                });
            }

            // assemble and sign the full component source
            var source = content + EOL + previous + EOL + certificate;
            const signature = privateAPI.sign(source);

            // construct the notarized document
            const document = bali.catalog({
                $content: content,
                $previous: previous,
                $certificate: certificate,
                $signature: signature
            });

            return document;
        },

        /**
         * This method generates a document citation for the specified document.
         * 
         * @param {Catalog} document The document to be cited.
         * @returns {Catalog} A document citation for the document.
         */
        citeDocument: function(document) {
            const parameters = document.getValue('$content').getParameters();
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
            const protocol = citation.getValue('$protocol');
            if (!publicAPI.protocol.isEqualTo(protocol)) {
                throw bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$documentMatches',
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: '"The protocol for the citation is not supported."'
                });
            }
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
            const protocol = certificate.getParameters().getParameter('$protocol');
            if (!publicAPI.protocol.isEqualTo(protocol)) {
                throw bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$documentIsValid',
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: '"The protocol for the notary certificate is not supported."'
                });
            }
            var source = document.getValue('$content') + EOL;
            source += document.getValue('$previous') + EOL;
            source += document.getValue('$certificate');
            var publicKey = certificate.getValue('$publicKey');
            var signature = document.getValue('$signature');
            var isValid = publicAPI.verify(source, publicKey, signature);
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
            const protocol = certificate.getParameters().getParameter('$protocol');
            if (!publicAPI.protocol.isEqualTo(protocol)) {
                throw bali.exception({
                    $module: '$DigitalNotary',
                    $function: '$encryptMessage',
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: '"The protocol for the notary certificate is not supported."'
                });
            }
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
                    $function: '$decryptMessage',
                    $exception: '$missingKey',
                    $tag: notaryTag,
                    $message: '"The notary key is missing."'
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
function storeConfiguration(configDirectory, configFilename, citation) {
    try {
        const configFile = configDirectory + configFilename;
        const source = citation.toString() + EOL;  // add POSIX compliant end of line
        fs.writeFileSync(configFile, source, {encoding: 'utf8', mode: 384});  // -rw------- permissions
    } catch (e) {
        throw bali.exception({
            $module: '$DigitalNotary',
            $function: '$generateKeys',
            $exception: '$configurationAccess',
            $directory: '"' + configDirectory + '"',
            $filename: '"' + configFilename + '"',
            $message: '"' + EOL + 'Unable to store the configuration file: ' + EOL + e + EOL + '"'
        });
    }
}

/*
 * This function loads the digital notary configuration citation from the specified
 * configuration directory and filename.
 */
function retrieveConfiguration(configDirectory, configFilename) {
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
            $function: '$api',
            $exception: '$configurationAccess',
            $directory: '"' + configDirectory + '"',
            $filename: '"' + configFilename + '"',
            $message: '"' + EOL + 'Unable to retrieve the current configuration file, or create a new one: ' + EOL + e + EOL + '"'
        });
    }
}

/*
 * This function connects to a remote hardware security module which implements all API
 * methods that utilize the private key.
 */
function connectToHSM(notaryTag, testDirectory) {
    try {
        // connect to the private hardware security module for the account
        const privateAPI = testDirectory ? 
            // use a test software security module (SSM)
            version.v1Test.api(notaryTag, testDirectory) : 
            // or, use a proxy to a hardware security module (HSM)
            version.v1Proxy.api(notaryTag);
        return privateAPI;
    } catch (e) {
        throw bali.exception({
            $module: '$DigitalNotary',
            $function: '$api',
            $exception: '$hsmAccess',
            $tag: notaryTag,
            $testMode: testDirectory ? true : false,
            $message: '"' + EOL + 'Unable to access the hardware security module (HSM): ' + EOL + e + EOL + '"'
        });
    }
}
