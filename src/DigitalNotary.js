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
const NotarizedDocument = require('./NotarizedDocument').NotarizedDocument;
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
            var versions = bali.list([publicAPI.PROTOCOL]);
            return versions;
        },

        /**
         * This method (re)generates a private notary key and its associated public notary
         * certificate. The private notary key is generated on the hardware security module
         * and remains there. The associated public notary certificate is returned and a
         * document citation for the certificate is stored in the local configuration
         * directory.
         * 
         * @returns {NotarizedDocument} A new Bali Notarized Document™ containing the public
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
         * @returns {NotarizedDocument} The notarized document containing the public certificate
         * for this digital notary.
         */
        getCertificate: function() {
            return privateAPI.certificate();
        },

        /**
         * This method creates a new document citation containing the specified document tag,
         * version, and (optionally) a digest of the document. If the document does not yet
         * exist, no digest is required (or even possible).
         * 
         * @param {Tag} tag The unique tag that identifies the document.
         * @param {Version} version The current version of the document.
         * @param {Binary} digest A base 32 encoded binary digital digest of the entire
         * contents of the document.
         * @returns {Catalog} A new document citation for the document.
         */
        createCitation: function(tag, version, digest) {
            return publicAPI.citationFromAttributes(tag, version, digest);
        },

        /**
         * This method creates a new reference to the document referred to by the specified
         * document citation.
         * 
         * @param {Catalog} citation The document citation to be used to create the reference.
         * @returns {Reference} A new reference to the document with the document citation
         * attributes encoded in it using the Bali Document Notation™.
         */
        createReference: function(citation) {
            return publicAPI.referenceFromCitation(citation);
        },

        /**
         * This method extracts from the specified Bali reference the certificate citation
         * encoded using the Bali Document Notation™.
         * 
         * @param {Reference} reference A reference containing the encoded document
         * citation.
         * @returns {Catalog} The document citation that was encoded in the specified reference.
         */
        extractCitation: function(reference) {
            return publicAPI.citationFromReference(reference);
        },

        /**
         * This method digitally notarizes the specified document using the private notary
         * key maintained inside the hardware security module. The specified document citation
         * is updated with the digest of the notarized document. The newly notarized document
         * is returned.
         * 
         * @param {Catalog} citation A document citation referencing the document to
         * be notarized.
         * @param {String} document The document to be notarized.
         * @param {Reference} previous A reference to the previous version of the document.
         * @returns {NotarizedDocument} The newly notarized document.
         */
        notarizeDocument: function(citation, document, previous) {
            previous = previous || bali.NONE;
            var certificateCitation = privateAPI.citation();
            if (!certificateCitation) {
                throw bali.exception({
                    $exception: '$missingKey',
                    $tag: privateAPI.tag,
                    $message: '"The notary key is missing."'
                });
            }
            var certificate = publicAPI.referenceFromCitation(certificateCitation);
            // assemble the full document source to be digitally signed
            var source = '';
            source += certificate + EOL;
            source += previous + EOL;
            source += document;
            // prepend the digital signature to the document source
            source = privateAPI.sign(source) + EOL + source;
            // construct the notarized document
            var notarizedDocument = NotarizedDocument.fromString(source);
            // update the document citation with the new digest
            citation.setValue('$digest', publicAPI.digest(source));
            return notarizedDocument;
        },

        /**
         * This method parses the source string for a notarized document and returns the
         * corresponding document.
         * 
         * @param {String} source A string containing the source for the notarized document.
         * @returns {NotarizedDocument}
         */
        parseDocument: function(source) {
            return NotarizedDocument.fromString(source);
        },

        /**
         * This method determines whether or not the specified document citation matches
         * the specified document. The citation only matches if its digest matches the
         * digest of the document.
         * 
         * @param {Catalog} citation A document citation allegedly referring to the
         * specified document.
         * @param {NotarizedDocument} document The document to be tested.
         * @returns {Boolean} Whether or not the citation matches the specified document.
         */
        documentMatches: function(citation, document) {
            var protocol = citation.getValue('$protocol');
            if (protocol.toString() === publicAPI.PROTOCOL) {
                var digest = publicAPI.digest(document);
                return digest.isEqualTo(citation.getValue('$digest'));
            } else {
                throw bali.exception({
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: '"The protocol for the citation is not supported."'
                });
            }
        },

        /**
         * This method determines whether or not the notary seal on the specified document
         * is valid.
         * 
         * @param {Catalog} certificate A catalog containing the public notary key for the
         * private notary key that allegedly notarized the specified document.
         * @param {NotarizedDocument} document The notarized document to be tested.
         * @returns {Boolean} Whether or not the notary seal on the document is valid.
         */
        documentIsValid: function(certificate, document) {
            // check to see if the document's seal is valid
            var protocol = certificate.getValue('$protocol');
            if (protocol.toString() === publicAPI.PROTOCOL) {
                // extracting the digital signature from the beginning of the notarized document
                var source = '';
                source += document.certificate + EOL;
                source += document.previous + EOL;
                source += document.content;
                // verify the digital signature using the public key from the notary certificate
                var publicKey = certificate.getValue('$publicKey');
                var signature = document.signature;
                var isValid = publicAPI.verify(publicKey, source, signature);
                return isValid;
            } else {
                throw bali.exception({
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: '"The protocol for the notary certificate is not supported."'
                });
            }
        },

        /**
         * This method uses the specified public notary certificate to encrypt the specified
         * message in such a way that only the intended recipient of the encrypted message can
         * decrypt it using their private notary key. The result is an authenticated encrypted
         * message (AEM) containing the ciphertext and other required attributes needed to
         * decrypt the message.
         * 
         * @param {Catalog} certificate A catalog containing the public notary key for the
         * intended recipient of the encrypted message.
         * @param {String} message The plaintext message to be encrypted using the specified
         * public notary certificate.
         * @returns {Catalog} An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes for the specified message.
         */
        encryptMessage: function(certificate, message) {
            var protocol = certificate.getValue('$protocol');
            var publicKey = certificate.getValue('$publicKey');
            if (protocol.toString() === publicAPI.PROTOCOL) {
                var aem = publicAPI.encrypt(publicKey, message);
                return aem;
            } else {
                throw bali.exception({
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: '"The protocol for the notary certificate is not supported."'
                });
            }
        },

        /**
         * This method uses the private notary key in the hardware security module to decrypt
         * the ciphertext residing in the specified authenticated encrypted message (AEM). THe
         * result is the decrypted plaintext message.
         * 
         * @param {Catalog} aem An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes required to decrypt the message.
         * @returns {String} The decrypted plaintext message.
         */
        decryptMessage: function(aem) {
            if (!privateAPI.citation()) {
                throw bali.exception({
                    $exception: '$missingKey',
                    $tag: notaryTag,
                    $message: '"The notary key is missing."'
                });
            }
            var protocol = aem.getValue('$protocol');
            if (protocol.toString() === publicAPI.PROTOCOL) {
                var message = privateAPI.decrypt(aem);
                return message;
            } else {
                throw bali.exception({
                    $exception: '$unsupportedProtocol',
                    $protocol: protocol,
                    $message: '"The protocol for the encrypted message is not supported."'
                });
            }
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
            certificateCitation = publicAPI.citationFromAttributes();
            source = certificateCitation.toString() + EOL;  // add POSIX compliant end of line
            fs.writeFileSync(configFile, source, {encoding: 'utf8', mode: 384});  // -rw------- permissions
        }
        return certificateCitation;
    } catch (e) {
        throw bali.exception({
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
            $exception: '$hsmAccess',
            $tag: notaryTag,
            $testMode: testDirectory ? true : false,
            $message: '"' + EOL + 'Unable to access the hardware security module (HSM): ' + EOL + e + EOL + '"'
        });
    }
}
