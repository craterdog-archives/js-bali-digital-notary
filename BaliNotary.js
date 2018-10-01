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
var homeDirectory = require('os').homedir() + '/.bali/';
var fs = require('fs');
var BaliDocument = require('bali-document-notation/BaliDocument');
var codex = require('bali-document-notation/utilities/EncodingUtilities');
var V1 = require('./protocols/V1');
var V1Public = require('./protocols/V1Public');
var V1Proxy = require('./protocols/V1Proxy');  // proxy to a hardware security module
var V1Test = require('./protocols/V1Private');   // local test software secutity module


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
    var certificateCitation = loadCitation(filename);

    // retrieve the notary key for the account
    var tag = Citation.fromReference(certificateCitation).tag;
    var notaryKey;
    if (testDirectory) {
        notaryKey = V1Test.notaryKey(tag, testDirectory);
    } else {
        notaryKey = V1Proxy.notaryKey(tag);
    }

    return {

        generateKeys: function() {
            var result = notaryKey.generate();
            var certificate = BaliDocument.fromSource(result.source);
            certificateCitation = result.citation;
            storeCitation(filename, certificateCitation);
            return certificate;
        },

        regenerateKeys: function() {
            var result = notaryKey.regenerate();
            var certificate = BaliDocument.fromSource(result.source);
            certificateCitation = result.citation;
            storeCitation(filename, certificateCitation);
            return certificate;
        },

        citation: function() {
            return certificateCitation;
        },

        notarizeDocument: function(tag, version, document) {
            if (!notaryKey.citation()) {
                throw new Error('NOTARY: The following notary key has not yet been generated: ' + tag);
            }

            // prepare the document source for signing
            var source = document.toSource();
            source += certificateCitation;  // NOTE: the citation must be included in the signed source!

            // generate the notarization signature
            var signature = notaryKey.sign(source);

            // append the notary seal to the document (modifies it in place)
            document.addNotarySeal(certificateCitation, signature);

            // generate a citation to the notarized document
            source = document.toSource();  // get updated source
            var citation = V1.cite(tag, version, source);

            return citation;
        },

        documentMatches: function(citation, document) {
            var documentCitation = Citation.fromReference(citation);
            var protocol = documentCitation.protocol;
            switch(protocol) {
                case V1.PROTOCOL:
                    var digest = V1.digest(document.toSource());
                    return documentCitation.digest === digest;
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

                    // calculate the digest of the stripped document + certificate citation
                    var source = stripped.toSource();
                    // NOTE: the certificate citation must be included in the signed source!
                    var citation = seal.children[0].toString();
                    source += citation;

                    // verify the signature using the public key from the notary certificate
                    var publicKey = certificate.getString('$publicKey');
                    var signature = seal.children[1].toString();
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
            if (!notaryKey.citation()) {
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


function Citation(protocol, tag, version, digest) {
    this.protocol = protocol;
    this.tag = tag;
    this.version = version;
    this.digest = digest.replace(/\s/g, '');
    return this;
}
Citation.prototype.constructor = Citation;
exports.Citation = Citation;


Citation.fromScratch = function() {
    var protocol = V1.PROTOCOL;
    var tag = codex.randomTag();
    var version = 'v1';
    var digest = 'none';
    var citation = new Citation(protocol, tag, version, digest);
    return citation;
};


Citation.fromSource = function(source) {
    var document = BaliDocument.fromSource(source);
    var protocol = document.getString('$protocol');
    var tag = document.getString('$tag');
    var version = document.getString('$version');
    var digest = document.getString('$digest').replace(/\s/g, '');
    var citation = new Citation(protocol, tag, version, digest);
    return citation;
};


Citation.fromReference = function(reference) {
    reference = reference.toString();
    var source = reference.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var document = BaliDocument.fromSource(source);
    var protocol = document.getString('$protocol');
    var tag = document.getString('$tag');
    var version = document.getString('$version');
    var digest = document.getString('$digest').replace(/\s/g, '');
    var citation = new Citation(protocol, tag, version, digest);
    return citation;
};


Citation.prototype.toString = function() {
    var source = this.toSource();
    return source;
};


Citation.prototype.toReference = function() {
    var reference = '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>';
    reference = reference.replace(/%protocol/, this.protocol);
    reference = reference.replace(/%tag/, this.tag);
    reference = reference.replace(/%version/, this.version);
    reference = reference.replace(/%digest/, this.digest);
    return reference;
};


Citation.prototype.toSource = function(indentation) {
    indentation = indentation ? indentation : '';
    var source =  '[\n' +
        indentation + '    $protocol: %protocol\n' +
        indentation + '    $tag: %tag\n' +
        indentation + '    $version: %version\n' +
        indentation + '    $digest: %digest\n' +
        indentation + ']\n';
    source = source.replace(/%protocol/, this.protocol);
    source = source.replace(/%tag/, this.tag);
    source = source.replace(/%version/, this.version);
    source = source.replace(/%digest/, this.digest);
    return source;
};

// PRIVATE FUNCTIONS

function loadCitation(filename) {
    var citation;
    var source;
    if (fs.existsSync(filename)) {
        source = fs.readFileSync(filename).toString();
        citation = Citation.fromSource(source);
    } else {
        citation = Citation.fromScratch();
        source = citation.toSource();
        fs.writeFileSync(filename, source, {mode: 384});  // -rw------- permissions
    }
    var reference = citation.toReference();
    return reference;
}

function storeCitation(filename, reference) {
    var citation = Citation.fromReference(reference);
    var source = citation.toSource();
    fs.writeFileSync(filename, source, {mode: 384});  // -rw------- permissions
}
