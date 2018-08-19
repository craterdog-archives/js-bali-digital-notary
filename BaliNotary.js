/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
var bali = require('bali-document-notation/BaliDocuments');
var V1 = require('./protocols/V1').V1;
var V1Public = require('./protocols/V1Public').V1Public;
var V1Proxy = require('./protocols/V1Proxy');  // proxy to a hardware security module
var V1Test = require('./protocols/V1Private');   // local test software secutity module


/**
 * This function returns the Bali Notary™ for the specified account tag.
 * 
 * @param {String} tag The unique tag for the account.
 * @param {String} testing Any string signifying that this notary is only being used for
 * local testing and is not a secure implementation.
 * @returns {Object} The Bali Notary™ for the specified account.
 */
exports.loadNotary = function(tag, testing) {

    var notaryKey = (testing ? V1Test : V1Proxy).getNotaryKey(tag);

    return {
        generateKeys: function() {
            var certificate = notaryKey.generate();
            var reference = certificate.reference;
            certificate = bali.parseDocument(certificate.source);
            return {
                reference: reference,
                citation: citation(reference),
                certificate: certificate
            };
        },

        regenerateKeys: function() {
            var certificate = notaryKey.regenerate();
            var reference = certificate.reference;
            certificate = bali.parseDocument(certificate.source);
            return {
                reference: reference,
                citation: citation(reference),
                certificate: certificate
            };
        },
        
        notarizeDocument: function(tag, version, document) {
            if (!notaryKey.reference()) {
                throw new Error('NOTARY: The following notary key has not yet been generated: ' + tag);
            }
            if (!bali.isTag(tag)) {
                throw new Error('NOTARY: The function was passed an invalid Bali tag: ' + tag);
            }
            if (!bali.isVersion(version)) {
                throw new Error('NOTARY: The function was passed an invalid Bali version: ' + version);
            }
            if (!bali.isDocument(document)) {
                throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
            }
        
            // prepare the document source for signing
            var reference = notaryKey.reference();
            var source = document.toString();
            source += reference + '\n';  // NOTE: the reference must be included in the signed source!
        
            // generate the notarization signature
            var signature = notaryKey.sign(source);
        
            // append the notary seal to the document (modifies it in place)
            bali.addSeal(document, reference, signature);
        
            // generate a citation to the notarized document
            source = document.toString();  // get updated source
            reference = V1.cite(tag, version, source);
            return citation(reference);
        },
        
        documentMatches: function(citation, document) {
            if (!isCitation(citation)) {
                throw new Error('NOTARY: The function was passed an invalid document citation: ' + citation);
            }
            if (!bali.isDocument(document)) {
                throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
            }
            var protocol = citation.protocol;
            switch(protocol) {
                case V1.PROTOCOL:
                    var digest = V1.digest(document.toString());
                    return citation.digest === digest;
                default:
                    throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        },
        
        documentIsValid: function(certificate, document) {
            if (!bali.isDocument(certificate)) {
                throw new Error('NOTARY: The function was passed an invalid Bali certificate: ' + certificate);
            }
            if (!bali.isDocument(document)) {
                throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
            }
        
            // check to see if the document's seal is valid
            var protocol = bali.getStringForKey(certificate, '$protocol');
            var publicKey = bali.getStringForKey(certificate, '$publicKey');
            switch(protocol) {
                case V1.PROTOCOL:
                    // strip off the last seal from the document
                    var seal = bali.getSeal(document);
                    var stripped = bali.removeSeal(document);
        
                    // calculate the digest of the stripped document + certificate reference
                    var source = stripped.toString();
                    // NOTE: the certificate reference must be included in the signed source!
                    var reference = bali.getReference(seal);
                    source += reference + '\n';
        
                    // verify the signature using the public key from the notary certificate
                    var signature = bali.getSignature(seal);
                    var isValid = V1Public.verify(publicKey, source, signature);
                    return isValid;
                default:
                    throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
            }
        },
        
        encryptMessage: function(certificate, message) {
            if (!bali.isDocument(certificate)) {
                throw new Error('NOTARY: The function was passed an invalid Bali certificate: ' + certificate);
            }
            var protocol = bali.getStringForKey(certificate, '$protocol');
            var publicKey = bali.getStringForKey(certificate, '$publicKey');
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
                throw new Error('NOTARY: The following notary key has not yet been generated: ' + tag);
            }
            if (!isAEM(aem)) {
                throw new Error('NOTARY: The function was passed an invalid authenticated encrypted message: ' + aem);
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

function isAEM(aem) {
    return aem &&
            aem.constructor.name === 'Object' &&
            aem.protocol &&
            aem.iv &&
            aem.auth &&
            aem.seed &&
            aem.ciphertext;
}

function isCitation(citation) {
    return citation &&
            citation.constructor.name === 'Object' &&
            citation.protocol &&
            citation.tag &&
            citation.version;
}

function citation(reference) {
    var source = reference.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var catalog = bali.parseComponent(source);
    var citation = {
        protocol: bali.getStringForKey(catalog, '$protocol'),
        tag: bali.getStringForKey(catalog, '$tag'),
        version: bali.getStringForKey(catalog, '$version'),
        digest: bali.getStringForKey(catalog, '$digest'),
        toString: function() {
            var source = V1.CITATION_TEMPLATE;
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%digest/, this.digest);
            return source;
        },
        toReference: function() {
            var source = V1.REFERENCE_TEMPLATE;
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%digest/, this.digest);
            return source;
        }
    };
    return citation;
}
