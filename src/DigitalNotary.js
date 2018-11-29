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
var fs = require('fs');
var configDirectory = require('os').homedir() + '/.bali/';  // default configuration directory
var bali = require('bali-component-framework');
var V1Public = require('./v1/V1Public');
var NotarizedDocument = require('./NotarizedDocument').NotarizedDocument;


/**
 * This function returns an object that implements the API for a digital notary.
 * 
 * @param {String} testDirectory The location of the test directory to be used for local
 * configuration storage. If not specified, the location of the configuration is in
 * '~/.bali/'.
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.api = function(testDirectory) {

    // create the config directory if necessary
    if (testDirectory) configDirectory = testDirectory;
    if (!fs.existsSync(configDirectory)) fs.mkdirSync(configDirectory, 448);  // drwx------ permissions

    // load the account citation
    var filename = configDirectory + 'Citation.bali';
    var certificateCitation = loadCitation(filename);

    // connect to the private hardware security module for the account
    var notaryTag = certificateCitation.getValue('$tag');
    var V1Private;
    if (testDirectory) {
        // use a test software security module instead
        V1Private = require('./v1/V1Test').api(notaryTag, testDirectory);
    } else {
        // use a proxy to a hardware security module
        V1Private = require('./v1/V1Proxy').api(notaryTag);
    }

    return {

        /**
         * This method returns a Bali Notarized Document™ containing the public certificate for
         * this digital notary.
         * 
         * @returns {NotarizedDocument} The notarized document containing the public certificate
         * for this digital notary.
         */
        getNotaryCertificate: function() {
            return V1Private.certificate();
        },

        /**
         * This method returns a document citation referencing the Bali Notarized Document™
         * containing the public certificate for this digital notary.
         * 
         * @returns {Catalog} A document citation referencing the document containing the
         * public certificate for this digital notary.
         */
        getNotaryCitation: function() {
            return V1Private.citation();
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
            return V1Public.citationFromReference(reference);
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
            return V1Public.citationFromAttributes(tag, version, digest);
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
            return V1Public.referenceFromCitation(citation);
        },

        parseDocument: function(string) {
            return NotarizedDocument.fromString(string);
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
            var notaryCertificate = V1Private.generate();
            var certificateCitation = V1Private.citation();
            storeCitation(filename, certificateCitation);
            return notaryCertificate;
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
            previous = previous || bali.Filter.NONE;
            var certificateCitation = V1Private.citation();
            if (!certificateCitation) {
                throw new Error('NOTARY: The following notary key has not yet been generated: ' + notaryTag);
            }
            var certificate = V1Public.referenceFromCitation(certificateCitation);
            // assemble the full document source to be digitally signed
            var source = '';
            source += certificate + '\n';
            source += previous + '\n';
            source += document;
            // prepend the digital signature to the document source
            source = V1Private.sign(source) + '\n' + source;
            // construct the notarized document
            var notarizedDocument = NotarizedDocument.fromString(source);
            // update the document citation with the new digest
            citation.setValue('$digest', V1Public.digest(source));
            return notarizedDocument;
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
            if (protocol.toString() === V1Public.PROTOCOL) {
                var digest = V1Public.digest(document);
                return digest.isEqualTo(citation.getValue('$digest'));
            } else {
                throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
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
            if (protocol.toString() === V1Public.PROTOCOL) {
                // extracting the digital signature from the beginning of the notarized document
                var source = '';
                source += document.certificate + '\n';
                source += document.previous + '\n';
                source += document.content;
                // verify the digital signature using the public key from the notary certificate
                var publicKey = certificate.getValue('$publicKey');
                var signature = document.signature;
                var isValid = V1Public.verify(publicKey, source, signature);
                return isValid;
            } else {
                throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
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
            if (protocol.toString() === V1Public.PROTOCOL) {
                var aem = V1Public.encrypt(publicKey, message);
                return aem;
            } else {
                throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
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
            if (!V1Private.citation()) {
                throw new Error('NOTARY: The notary key has not yet been generated.');
            }
            var protocol = aem.getValue('$protocol');
            if (protocol.toString() === V1Public.PROTOCOL) {
                var message = V1Private.decrypt(aem);
                return message;
            } else {
                throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        }

    };
};


// PRIVATE FUNCTIONS

/*
 * This function loads from the specified file a document citation. If the document citation
 * does not yet exist a new document citation with a new unique identifier tag is created and
 * stored in the file.
 */
function loadCitation(filename) {
    var source;
    var citation;
    if (fs.existsSync(filename)) {
        source = fs.readFileSync(filename, 'utf8');
        citation = bali.parser.parseDocument(source);
    } else {
        citation = V1Public.citationFromAttributes();
        storeCitation(filename, citation);
    }
    return citation;
}

/*
 * This function stores the specified document citation into the specified file.
 */
function storeCitation(filename, citation) {
    var source = citation.toString() + '\n';  // add POSIX compliant end of line
    fs.writeFileSync(filename, source, {encoding: 'utf8', mode: 384});  // -rw------- permissions
}
