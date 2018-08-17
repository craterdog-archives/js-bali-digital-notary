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
var codex = require('bali-document-notation/utilities/EncodingUtilities');
var V1 = require('./protocols/V1').V1;


/**
 * This function returns the notary key that is defined in the specified Bali document.
 * 
 * @param {Document} document The Bali document containing the notary key definition.
 * @returns {NotaryKey} The resulting notary key.
 */
exports.notaryKey = function(document) {
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
    }

    var protocol = bali.getStringForKey(document, '$protocol');
    switch(protocol) {
        case V1.PROTOCOL:
            // extract the unique tag and version number for this notary key
            var tag = bali.getStringForKey(document, '$tag');
            var version = bali.getStringForKey(document, '$version');
            var publicKey = bali.getStringForKey(document, '$publicKey');
            var citation = bali.getStringForKey(document, '$citation');
            var notaryKey = V1.recreate(tag, version, publicKey, citation);
            return notaryKey;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function generates a new notary key pair and returns the notary key
 * and its corresponding notary certificate in an object.
 * 
 * @param {String} protocol The Bali version string for the protocol to use to generate the
 * keypair.
 * @returns {Object} The resulting notary key and certificate.
 */
exports.generateKeys = function(protocol) {
    // validate the argument
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The function was passed an invalid protocol: ' + protocol);
    }

    // generate the correct protocol version of the notary key pair
    switch(protocol) {
        case V1.PROTOCOL:
            // generate a new notary key
            var notaryKey = V1.generate();
            var tag = notaryKey.tag;
            var version = notaryKey.version;
            var publicKey = notaryKey.publicKey;

            // create the certificate document
            var source = V1.certificate(tag, version, publicKey);
            var certificate = bali.parseDocument(source);

            // notarize the certificate document
            notaryKey.citation = exports.notarizeDocument(notaryKey, tag, version, certificate);

            return {
                notaryKey: notaryKey,
                certificate: certificate
            };
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function regenerates a notary key and associated notary certificate. It
 * uses the old notary key to notarize the new notary certificate to prove its
 * place in the notary certificate chain.
 * 
 * @param {NotaryKey} notaryKey The existing notary key to be regenerated.
 * @returns {NotaryCertificate} The new notary certificate.
 */
exports.regenerateKeys = function(notaryKey) {
    // validate the argument
    if (!isNotaryKey(notaryKey)) {
        throw new Error('NOTARY: The function was passed an invalid notary key: ' + notaryKey);
    }

    // generate the correct protocol version of the notary key pair
    var protocol = notaryKey.protocol;
    switch(protocol) {
        case V1.PROTOCOL:
            // generate a new notary key
            var newKey = V1.generate(notaryKey);
            var tag = newKey.tag;
            var version = newKey.version;
            var publicKey = newKey.publicKey;

            // create the certificate document
            var source = V1.certificate(tag, version, publicKey);
            var certificate = bali.parseDocument(source);

            // notarize the new certificate with the old key and new key
            exports.notarizeDocument(notaryKey, tag, version, certificate);
            V1.forget(notaryKey);
            newKey.citation = exports.notarizeDocument(newKey, tag, version, certificate);

            return {
                notaryKey: newKey,
                certificate: certificate
            };
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function digitally notarizes a Bali document using this notary key. The resulting
 * notary seal is appended to the document and can be validated using the
 * <code>documentIsValid()</code> function on the associated notary certificate.
 * 
 * @param {NotaryKey} notaryKey The notary key to be used to notarize the document.
 * @param {String} tag The unique tag for the document to be notarized.
 * @param {String} version The version number of the document to be notarized.
 * @param {Document} document The document to be notarized.
 * @returns {String} A citation to the resulting notarized document.
 */
exports.notarizeDocument = function(notaryKey, tag, version, document) {
    // validate the arguments
    if (!isNotaryKey(notaryKey)) {
        throw new Error('NOTARY: The function was passed an invalid notary key: ' + notaryKey);
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
    var protocol = notaryKey.protocol;
    var certificateCitation = notaryKey.citation;
    switch(protocol) {
        case V1.PROTOCOL:
            // prepare the document source
            var source = document.toString();
            source += certificateCitation;  // NOTE: the citation must be included in the signed source!

            // generate the notarization signature
            var signature = V1.sign(notaryKey, source);

            // append the notary seal to the document
            bali.addSeal(document, certificateCitation, signature);

            // generate a citation to the notarized document
            var documentCitation = V1.cite(tag, version, document.toString());
            return documentCitation;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function reconstructs an existing document citation from its attributes.
 * 
 * @param {String} tag The unique tag for the cited document.
 * @param {String} version The version string for the cited document.
 * @param {String} hash The cryptographic hash of the cited document.
 * @returns {String} The reconstructed document citation.
 */
exports.citation = function(tag, version, hash) {
    var citation = V1.citation(tag, version, hash);
    return citation;
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
 * This function decrypts an authenticated encrypted message generated using the notary
 * certificate associated with this notary key. The notary certificate generated and
 * encrypted a random secret key that was used to encrypt the original message. The
 * decrypted message is returned from this function.
 * 
 * @param {NotaryKey} notaryKey The notary key to be used to decrypt the message.
 * @param {Object} aem The authenticated encrypted message.
 * @returns {String} The decrypted message.
 */
exports.decryptMessage = function(notaryKey, aem) {
    // validate the arguments
    if (!isNotaryKey(notaryKey)) {
        throw new Error('NOTARY: The function was passed an invalid notary key: ' + notaryKey);
    }
    var protocol = notaryKey.protocol;
    switch(protocol) {
        case V1.PROTOCOL:
            var message = V1.decrypt(notaryKey, aem);
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
        case V1.PROTOCOL:
            // strip off the last seal from the document
            var seal = bali.getSeal(document);
            var stripped = bali.removeSeal(document);

            // calculate the hash of the stripped document + certificate citation
            var source = stripped.toString();
            // NOTE: the certificate citation must be included in the signed source!
            var citation = bali.getCitation(seal);
            source += citation;

            // verify the signature using the public key from the notary certificate
            var signature = bali.getSignature(seal);
            var isValid = V1.verify(publicKey, source, signature);
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
        case V1.PROTOCOL:
            var aem = V1.encrypt(publicKey, message);
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
        case V1.PROTOCOL:
            return hash === V1.digest(document.toString());
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


// PRIVATE FUNCTIONS

function isNotaryKey(notaryKey) {
    return notaryKey ? true : false;
}

function isCitation(citation) {
    return citation ? true : false;
}