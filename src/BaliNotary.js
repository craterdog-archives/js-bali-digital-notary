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
 * digital notary interface that is used for account identity purposes within the
 * Bali Cloud Environment™. If a test directory is specified, it will be created
 * and used as the location of the local key store. Otherwise, a proxy to a
 * hardware security module will be used for all private key operations.
 */
var fs = require('fs');
var homeDirectory = require('os').homedir() + '/.bali/';
var bali = require('bali-document-notation');
var V1 = require('./v1/V1');
var V1Public = require('./v1/V1Public');
var V1Private = require('./v1/V1Private');  // proxy to a hardware security module
var V1Test = require('./v1/V1Test');   // local test software secutity module


/**
 * This function returns an object that implements the API for a digital notary.
 * 
 * @param {String} testDirectory The location of the test directory to be used for local
 * configuration storage. If not specified, the location of the configuration is in
 * '~/.bali/'.
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.notaryKey = function(testDirectory) {

    // create the config directory if necessary
    if (testDirectory) homeDirectory = testDirectory;
    if (!fs.existsSync(homeDirectory)) fs.mkdirSync(homeDirectory, 448);  // drwx------ permissions

    // load the account citation
    var filename = homeDirectory + 'Citation.bali';
    var certificateCitation = loadCitation(filename);

    // retrieve the notary key for the account
    var notaryTag = certificateCitation.getValue('$tag');
    var securityModule;
    if (testDirectory) {
        securityModule = V1Test.securityModule(notaryTag, testDirectory);
    } else {
        securityModule = V1Private.securityModule(notaryTag);
    }

    return {

        getNotaryCertificate: function() {
            return securityModule.certificate();
        },

        getNotaryCitation: function() {
            return securityModule.citation();
        },

        extractCitation: function(reference) {
            return V1.citationFromReference(reference);
        },

        createCitation: function(tag, version, digest) {
            return V1.citationFromAttributes(tag, version, digest);
        },

        createReference: function(citation) {
            return V1.referenceFromCitation(citation);
        },

        generateKeys: function() {
            var notaryCertificate = securityModule.generate();
            var certificateCitation = securityModule.citation();
            storeCitation(filename, certificateCitation);
            return notaryCertificate;
        },

        notarizeDocument: function(citation, document) {
            var tag = citation.getValue('$tag');
            var version = citation.getValue('$version');

            // prepare the document source for signing
            var certificateCitation = securityModule.citation();
            if (!certificateCitation) {
                throw new Error('NOTARY: The following notary key has not yet been generated: ' + notaryTag);
            }
            var certificateReference = V1.referenceFromCitation(certificateCitation);
            var source = bali.formatter.formatComponent(document);
            source += certificateReference;  // NOTE: the reference must be included in the signed source!

            // generate the digital signature
            var digitalSignature = securityModule.sign(source);

            // append the notary seal to the document (modifies it in place)
            var seal = new bali.Seal(certificateReference, digitalSignature);
            document.addNotarySeal(seal);

            // generate a citation to the notarized document
            var citation = V1.cite(tag, version, document);

            return citation;
        },

        documentMatches: function(citation, document) {
            var protocol = citation.getValue('$protocol');
            if (protocol.equalTo(V1.PROTOCOL)) {
                var digest = V1.digest(document);
                return digest.equalTo(citation.getValue('$digest'));
            } else {
                throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        },

        documentIsValid: function(certificate, document) {
            // check to see if the document's seal is valid
            var protocol = certificate.getValue('$protocol');
            if (protocol.equalTo(V1.PROTOCOL)) {
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

        encryptMessage: function(certificate, message) {
            var protocol = certificate.getValue('$protocol');
            var publicKey = certificate.getValue('$publicKey');
            if (protocol.equalTo(V1.PROTOCOL)) {
                var aem = V1Public.encrypt(publicKey, message);
                return aem;
            } else {
                throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        },

        decryptMessage: function(aem) {
            if (!securityModule.citation()) {
                throw new Error('NOTARY: The notary key has not yet been generated.');
            }
            var protocol = aem.getValue('$protocol');
            if (protocol.equalTo(V1.PROTOCOL)) {
                var message = securityModule.decrypt(aem);
                return message;
            } else {
                throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        }

    };
};


// PRIVATE FUNCTIONS

function loadCitation(filename) {
    var source;
    var citation;
    if (fs.existsSync(filename)) {
        source = fs.readFileSync(filename).toString();
        var document = bali.parser.parseDocument(source);
        citation = document.documentContent;
    } else {
        citation = V1.citationFromScratch();
        storeCitation(filename, citation);
    }
    return citation;
}

function storeCitation(filename, citation) {
    var document = new bali.Document(undefined, citation);
    var source = document.toSource();
    fs.writeFileSync(filename, source, {mode: 384});  // -rw------- permissions
}
