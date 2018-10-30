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
 * purposes within the Bali Cloud Environment™. If a test directory is specified,
 * it will be created and used as the location of the local key store. Otherwise, a
 * proxy to a hardware security module will be used for all private key operations.
 */
var fs = require('fs');
var homeDirectory = require('os').homedir() + '/.bali/';
var bali = require('bali-document-framework');
var V1Public = require('./v1/V1Public');


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
    if (testDirectory) homeDirectory = testDirectory;
    if (!fs.existsSync(homeDirectory)) fs.mkdirSync(homeDirectory, 448);  // drwx------ permissions

    // load the account citation
    var filename = homeDirectory + 'Citation.bali';
    var certificateCitation = loadCitation(filename);

    // connect to the private hardware security module for the account
    var notaryTag = certificateCitation.getValue('$tag');
    var V1Private;
    if (testDirectory) {
        V1Private = require('./v1/V1Test').api(notaryTag, testDirectory);
    } else {
        V1Private = require('./v1/V1Proxy').api(notaryTag);
    }

    return {

        /**
         * This method returns the the Bali document containing the public certificate for this
         * notary.
         * 
         * @returns {Document} The Bali document containing the public certificate for this
         * notary.
         */
        getNotaryCertificate: function() {
            return V1Private.certificate();
        },

        /**
         * This method returns a document citation referencing the Bali document containing
         * the public certificate for this notary.
         * 
         * @returns {Catalog} A document citation referencing the Bali document containing
         * the public certificate for this notary.
         */
        getNotaryCitation: function() {
            return V1Private.citation();
        },

        /**
         * This method extracts from the specified Bali reference the encoded certificate
         * citation.
         * 
         * @param {Reference} reference A Bali reference containing an encoded document
         * citation.
         * @returns {Catalog} The document citation that was encoded in the specified reference.
         */
        extractCitation: function(reference) {
            return V1Public.citationFromReference(reference);
        },

        /**
         * This method creates a new document citation containing the specified document tag,
         * version, and (optional) digest of the document. If the document does not yet exist
         * no digest is needed.
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
         * @returns {Reference} A new reference to the document referred to by the document
         * citation.
         */
        createReference: function(citation) {
            return V1Public.referenceFromCitation(citation);
        },

        /**
         * This method (re)generates the private notary key and its associated public notary
         * certificate. The private notary key is generated on the hardware security module
         * and remains there. The associated public notary certificate is returned.
         * 
         * @returns {Document} The new Bali document containing the public notary certificate
         * associated with the new private notary key.
         */
        generateKeys: function() {
            var notaryCertificate = V1Private.generate();
            var certificateCitation = V1Private.citation();
            storeCitation(filename, certificateCitation);
            return notaryCertificate;
        },

        /**
         * This method digitally notarizes the specified document using the private notary
         * key inside the hardware security module. An updated document citation to the newly
         * notarized document is returned.
         * 
         * @param {Catalog} documentCitation A document citation referencing the document to
         * be notarized.
         * @param {Document} document The document to be notarized.
         * @returns {Catalog} The updated document citation referencing the notarized document.
         */
        notarizeDocument: function(documentCitation, document) {
            var tag = documentCitation.getValue('$tag');
            var version = documentCitation.getValue('$version');

            // prepare the document source for signing
            var certificateCitation = V1Private.citation();
            if (!certificateCitation) {
                throw new Error('NOTARY: The following notary key has not yet been generated: ' + notaryTag);
            }
            var certificateReference = V1Public.referenceFromCitation(certificateCitation);
            var source = bali.formatter.formatComponent(document);
            source += certificateReference;  // NOTE: the reference must be included in the signed source!

            // generate the digital signature
            var digitalSignature = V1Private.sign(source);

            // append the notary seal to the document (modifies it in place)
            var seal = new bali.Seal(certificateReference, digitalSignature);
            document.addNotarySeal(seal);

            // generate a citation to the notarized document
            documentCitation = V1Public.cite(tag, version, document);

            return documentCitation;
        },

        /**
         * This method determines whether or not the documentCitation matches the specified
         * document.
         * 
         * @param {Catalog} documentCitation A document citation allegedly referring to the
         * specified document.
         * @param {Document} document The document to be tested.
         * @returns {Boolean} Whether or not the documentCitation matches the specified document.
         */
        documentMatches: function(documentCitation, document) {
            var protocol = documentCitation.getValue('$protocol');
            if (protocol.toString() === V1Public.PROTOCOL) {
                var digest = V1Public.digest(document);
                return digest.equalTo(documentCitation.getValue('$digest'));
            } else {
                throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        },

        /**
         * This method determines whether or not the notary seal on the specified document
         * is valid.
         * 
         * @param {Document} certificate A document containing the public notary seal for
         * the private notary key that allegedly notarized the specified document.
         * @param {Document} document The document to be tested.
         * @returns {Boolean} Whether or not the notary seal on the document is valid.
         */
        documentIsValid: function(certificate, document) {
            // check to see if the document's seal is valid
            var protocol = certificate.getValue('$protocol');
            if (protocol.toString() === V1Public.PROTOCOL) {
                // strip off the last seal from the document
                var seal = document.getLastSeal();
                var stripped = document.unsealed();

                // calculate the digest of the stripped document + certificate reference
                var source = stripped.toSource();
                // NOTE: the certificate reference must be included in the signed source!
                source += seal.certificateReference.toString();

                // verify the digital signature using the public key from the notary certificate
                var publicKey = certificate.getValue('$publicKey');
                var digitalSignature = seal.digitalSignature;
                var isValid = V1Public.verify(publicKey, source, digitalSignature);
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
         * @param {Document} certificate A document containing the public notary certificate for
         * the intended recipient of the encrypted message.
         * @param {String} message The message to be encrypted using the specified public notary
         * certificate.
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
         * result is the decrypted message.
         * 
         * @param {Catalog} aem An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes required to decrypt the message.
         * @returns {String} The decrypted message.
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
        source = fs.readFileSync(filename).toString();
        var document = bali.parser.parseDocument(source);
        citation = document.documentContent;
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
    var document = new bali.Document(undefined, citation);
    var source = document.toSource();
    fs.writeFileSync(filename, source, {mode: 384});  // -rw------- permissions
}
