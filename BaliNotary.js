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
var V1Private = require('./protocols/V1Private').V1Private;
var V1Public = require('./protocols/V1Public').V1Public;


/**
 * This function generates a new notary key pair and returns the corresponding
 * notary certificate using the latest version of the protocol.
 * 
 * generate the keypair.
 * @returns {Object} The resulting citation and notary certificate.
 */
exports.generateKeys = function() {
    var source = V1Private.generate();
    var citation = V1Private.citation;
    var certificate = bali.parseDocument(source);
    return {
        citation: citation,
        certificate: certificate
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
exports.regenerateKeys = function() {
    var source = V1Private.regenerate();
    var citation = V1Private.citation;
    var certificate = bali.parseDocument(source);
    return {
        citation: citation,
        certificate: certificate
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
 * @returns {String} A citation to the resulting notarized document.
 */
exports.notarizeDocument = function(tag, version, document) {
    if (!bali.isTag(tag)) {
        throw new Error('NOTARY: The function was passed an invalid Bali tag: ' + tag);
    }
    if (!bali.isVersion(version)) {
        throw new Error('NOTARY: The function was passed an invalid Bali version: ' + version);
    }
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
    }
    var certificateCitation = V1Private.citation;
    var source = document.toString();
    source += certificateCitation + '\n';  // NOTE: the citation must be included in the signed source!

    // generate the notarization signature
    var signature = V1Private.sign(source);

    // append the notary seal to the document
    bali.addSeal(document, certificateCitation, signature);

    // generate a citation to the notarized document
    var documentCitation = V1Public.cite(tag, version, document.toString());
    return documentCitation;
};


/**
 * This function extracts the tag attribute from a document citation.
 * 
 * @param {type} citation The document citation.
 * @returns {String} The unique tag for the cited document.
 */
exports.getTag = function(citation) {
    var source = citation.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var catalog = bali.parseComponent(source);
    var tag = bali.getStringForKey(catalog, '$tag');
    return tag;
};


/**
 * This function extracts the version attribute from a document citation.
 * 
 * @param {type} citation The document citation.
 * @returns {String} The version string for the cited document.
 */
exports.getVersion = function(citation) {
    var source = citation.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var catalog = bali.parseComponent(source);
    var version = bali.getStringForKey(catalog, '$version');
    return version;
};


/**
 * This function extracts the hash attribute from a document citation.
 * 
 * @param {type} citation The document citation.
 * @returns {String} The unique hash for the cited document.
 */
exports.getHash = function(citation) {
    var source = citation.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var catalog = bali.parseComponent(source);
    var hash = bali.getStringForKey(catalog, '$hash');
    return hash;
};


/**
 * This function decrypts an authenticated encrypted message with the notary key using
 * the version of the protocol specified in the message.
 * 
 * @param {Object} aem The authenticated encrypted message.
 * @returns {String} The decrypted message.
 */
exports.decryptMessage = function(aem) {
    var protocol = aem.protocol;
    switch(protocol) {
        case V1Public.PROTOCOL:
            var message = V1Private.decrypt(aem);
            return message;
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
exports.documentIsValid = function(certificate, document) {
    // validate the arguments
    if (!bali.isDocument(certificate)) {
        throw new Error('NOTARY: The function was passed an invalid Bali certificate: ' + certificate);
    }
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
    }
    var protocol = bali.getStringForKey(certificate, '$protocol');
    var publicKey = bali.getStringForKey(certificate, '$publicKey');
    switch(protocol) {
        case V1Public.PROTOCOL:
            // strip off the last seal from the document
            var seal = bali.getSeal(document);
            var stripped = bali.removeSeal(document);

            // calculate the hash of the stripped document + certificate citation
            var source = stripped.toString();
            // NOTE: the certificate citation must be included in the signed source!
            var citation = bali.getCitation(seal);
            source += citation + '\n';

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
exports.encryptMessage = function(certificate, message) {
    // validate the arguments
    if (!bali.isDocument(certificate)) {
        throw new Error('NOTARY: The function was passed an invalid Bali certificate: ' + certificate);
    }
    var protocol = bali.getStringForKey(certificate, '$protocol');
    var publicKey = bali.getStringForKey(certificate, '$publicKey');
    switch(protocol) {
        case V1Public.PROTOCOL:
            var aem = V1Public.encrypt(publicKey, message);
            return aem;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function determines whether or not the specified document matches EXACTLY the
 * document referenced by this citation.
 * 
 * @param {String} citation A citation to the document to be checked.
 * @param {String} document The document to be checked.
 * @returns {Boolean} Whether or not the document hash value matches.
 */
exports.documentMatches = function(citation, document) {
    // validate the arguments
    if (!isCitation(citation)) {
        throw new Error('NOTARY: The function was passed an invalid document citation: ' + citation);
    }
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
    }
    var source = citation.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var catalog = bali.parseComponent(source);
    var protocol = bali.getStringForKey(catalog, '$protocol');
    var hash = bali.getStringForKey(catalog, '$hash');
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The constructor received a reference with an invalid protocol version: ' + protocol);
    }
    switch(protocol) {
        case V1Public.PROTOCOL:
            var h = V1Public.digest(document.toString());
            return hash === h;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


// PRIVATE FUNCTIONS

function isCitation(citation) {
    return citation ? true : false;
}