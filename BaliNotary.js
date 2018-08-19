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


// CONSTRUCTORS

exports.loadNotary = function(tag, testing) {
    var notary = new BaliNotary(tag, testing);
    return notary;
};
function BaliNotary(tag, testing) {
    this.tag = tag;
    this.notaryKey = (testing ? V1Test : V1Proxy).getNotaryKey(tag);
    return this;
}
BaliNotary.prototype.constructor = BaliNotary;


// PUBLIC INTERFACE

/**
 * This function generates a new notary key pair and returns the corresponding
 * notary certificate using the latest version of the protocol.
 * 
 * generate the keypair.
 * @returns {Object} The resulting citation and notary certificate.
 */
BaliNotary.prototype.generateKeys = function() {
    var source = this.notaryKey.generate();
    return {
        citation: citation(this.notaryKey.reference),
        certificate: bali.parseDocument(source)
    };
};


/**
 * This function regenerates a notary key and associated notary certificate using the
 * latest version of the protocol. It uses the old notary key to notarize the new notary
 * certificate first to prove its place in the notary certificate chain.
 * 
 * generate the keypair.
 * @returns {Object} The resulting citation and notary certificate.
 */
BaliNotary.prototype.regenerateKeys = function() {
    var source = this.notaryKey.regenerate();
    return {
        citation: citation(this.notaryKey.reference),
        certificate: bali.parseDocument(source)
    };
};


/**
 * This function digitally notarizes a Bali document with this notary key using the
 * latest protocol. The resulting notary seal is appended to the document and can be
 * validated using the <code>documentIsValid()</code> function on the associated
 * notary certificate.
 * 
 * @param {String} tag The unique tag for the document to be notarized.
 * @param {String} version The version number of the document to be notarized.
 * @param {Document} document The document to be notarized.
 * @returns {Object} A citation to the resulting notarized document.
 */
BaliNotary.prototype.notarizeDocument = function(tag, version, document) {
    // validate the arguments
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
    var reference = this.notaryKey.reference;
    var source = document.toString();
    source += reference + '\n';  // NOTE: the reference must be included in the signed source!

    // generate the notarization signature
    var signature = this.notaryKey.sign(source);

    // append the notary seal to the document (modifies it in place)
    bali.addSeal(document, reference, signature);

    // generate a citation to the notarized document
    source = document.toString();  // get updated source
    reference = V1.cite(tag, version, source);
    return citation(reference);
};


/**
 * This function determines whether or not the specified document matches EXACTLY the
 * document referenced by this citation.
 * 
 * @param {String} citation A citation to the document to be checked.
 * @param {Document} document The document to be checked.
 * @returns {Boolean} Whether or not the document digest value matches.
 */
BaliNotary.prototype.documentMatches = function(citation, document) {
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
};


/**
 * This function validates a Bali document that was notarized using the
 * <code>notarizeDocument</code> function on the associated notary key. This notary
 * certificate is used to verify the notary seal that is appended to the Bali
 * document.
 * 
 * @param {Document} certificate The Bali certificate to be used to validate the document.
 * @param {Document} document The Bali document that was notarized.
 * @returns {Boolean} Whether or not the notary seal on the document is valid.
 */
BaliNotary.prototype.documentIsValid = function(certificate, document) {
    // validate the arguments
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
};


/**
 * This function generates a random symmetric key and uses it to encrypt a message.  The
 * symmetric key is then encrypted by the notary certificate and an authenticated
 * encrypted message is returned. The resulting authenticated encrypted message can
 * be decrypted using the <code>decryptMessage</code> function on the corresponding
 * notary key.
 * 
 * @param {Document} certificate The Bali certificate to be used to encrypt the message.
 * @param {String} message The message to be encrypted.
 * @returns {Object} The resulting authenticated encrypted message.
 */
BaliNotary.prototype.encryptMessage = function(certificate, message) {
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
};


/**
 * This function decrypts an authenticated encrypted message with the notary key using
 * the version of the protocol specified in the message.
 * 
 * @param {Object} aem The authenticated encrypted message.
 * @returns {String} The decrypted message.
 */
BaliNotary.prototype.decryptMessage = function(aem) {
    if (!isAEM(aem)) {
        throw new Error('NOTARY: The function was passed an invalid authenticated encrypted message: ' + aem);
    }
    var protocol = aem.protocol;
    switch(protocol) {
        case V1.PROTOCOL:
            var message = this.notaryKey.decrypt(aem);
            return message;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
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
        }
    };
    return citation;
}
