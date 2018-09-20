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
var BaliCitation = require('./BaliCitation');
var parser = require('bali-document-notation/transformers/DocumentParser');
var V1 = require('./protocols/V1');
var V1Public = require('./protocols/V1Public');
var V1Proxy = require('./protocols/V1Proxy');  // proxy to a hardware security module
var V1Test = require('./protocols/V1Private');   // local test software secutity module
var homeDirectory = require('os').homedir() + '/.bali/';
var fs = require('fs');


/**
 * This function returns an object that implements the API for a digital notary.
 * 
 * @param {String} testDirectory The location of the test directory to be used for local
 * configuration storage. If not specified, the location of the configuration is in
 * '~/.bali/'.
 * @returns {Object} An object that implements the API for a digital notary.
 */
exports.notary = function(testDirectory) {

    // create the config directory if necessary
    if (testDirectory) homeDirectory = testDirectory;
    if (!fs.existsSync(homeDirectory)) fs.mkdirSync(homeDirectory, 448);  // drwx------ permissions

    // load the account citation
    var filename = homeDirectory + 'citation.bali';
    var citation = loadCitation(filename);

    // retrieve the notary key for the account
    var notaryKey;
    if (testDirectory) {
        notaryKey = V1Test.notaryKey(citation.tag, testDirectory);
    } else {
        notaryKey = V1Proxy.notaryKey(citation.tag);
    }

    return {

        generateKeys: function() {
            var result = notaryKey.generate();
            var certificate = parser.parseDocument(result.source);
            var reference = result.reference;
            citation = BaliCitation.fromReference(reference);
            storeCitation(filename, citation);
            return certificate;
        },

        regenerateKeys: function() {
            var result = notaryKey.regenerate();
            var certificate = parser.parseDocument(result.source);
            var reference = result.reference;
            citation = BaliCitation.fromReference(reference);
            storeCitation(filename, citation);
            return certificate;
        },

        citation: function() {
            return citation;
        },

        notarizeDocument: function(tag, version, document) {
            if (!notaryKey.reference()) {
                throw new Error('NOTARY: The following notary key has not yet been generated: ' + tag);
            }

            // prepare the document source for signing
            var reference = notaryKey.reference();
            var source = document.toSource();
            source += reference;  // NOTE: the reference must be included in the signed source!

            // generate the notarization signature
            var signature = notaryKey.sign(source);

            // append the notary seal to the document (modifies it in place)
            document.addSeal(reference, signature);

            // generate a citation to the notarized document
            source = document.toSource();  // get updated source
            reference = V1.cite(tag, version, source);
            var citation = BaliCitation.fromReference(reference);

            return citation;
        },

        documentMatches: function(citation, document) {
            var protocol = citation.protocol;
            switch(protocol) {
                case V1.PROTOCOL:
                    var digest = V1.digest(document.toSource());
                    return citation.digest === digest;
                default:
                    throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        },

        documentIsValid: function(certificate, document) {
            // check to see if the document's seal is valid
            var protocol = certificate.getString('$protocol');
            switch(protocol) {
                case V1.PROTOCOL:
                    // strip off the last seal from the document
                    var seal = document.getLastSeal();
                    var stripped = document.unsealed();

                    // calculate the digest of the stripped document + certificate reference
                    var source = stripped.toSource();
                    // NOTE: the certificate reference must be included in the signed source!
                    var reference = seal.certificateReference.toString();
                    source += reference;

                    // verify the signature using the public key from the notary certificate
                    var publicKey = certificate.getString('$publicKey');
                    var signature = seal.digitalSignature.toString();
                    var isValid = V1Public.verify(publicKey, source, signature);
                    return isValid;
                default:
                    throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        },

        encryptMessage: function(certificate, message) {
            var protocol = certificate.getString('$protocol');
            var publicKey = certificate.getString('$publicKey');
            switch(protocol) {
                case V1.PROTOCOL:
                    var aem = V1Public.encrypt(publicKey, message);
                    return aem;
                default:
                    throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        },

        decryptMessage: function(aem) {
            if (!notaryKey.reference()) {
                throw new Error('NOTARY: The notary key has not yet been generated.');
            }
            var protocol = aem.protocol;
            switch(protocol) {
                case V1.PROTOCOL:
                    var message = notaryKey.decrypt(aem);
                    return message;
                default:
                    throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        }
    };
};


// PRIVATE FUNCTIONS

function loadCitation(filename) {
    var citation;
    var source;
    if (fs.existsSync(filename)) {
        source = fs.readFileSync(filename).toString();
        citation = BaliCitation.fromSource(source);
    } else {
        citation = BaliCitation.fromScratch();
        source = citation.toSource();
        fs.writeFileSync(filename, source, {mode: 384});  // -rw------- permissions
    }
    return citation;
}

function storeCitation(filename, citation) {
    var source = citation.toSource();
    fs.writeFileSync(filename, source, {mode: 384});  // -rw------- permissions
}
