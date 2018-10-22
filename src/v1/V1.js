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
 * This module defines a library of constants and functions that are needed by the version
 * one (v1) security protocol implementation for the Bali Cloud Environment™.
 */
var crypto = require('crypto');
var bali = require('bali-document-notation');


// ALGORITHMS FOR THIS VERSION OF THE PROTOCOL

exports.PROTOCOL = new bali.Version('v1');
exports.CURVE = 'secp521r1';
exports.DIGEST = 'sha512';
exports.SIGNATURE = 'ecdsa-with-SHA1';
exports.CIPHER = 'aes-256-gcm';


// FUNCTIONS

/**
 * This function returns a cryptographically secure base 32 encoded digital digest of
 * the specified message. The digest is a Bali binary string and will always be the same
 * for the same message.
 * 
 * @param {Object} message The message to be digested.
 * @returns {Binary} A base 32 encoded digital digest of the message.
 */
exports.digest = function(message) {
    var hasher = crypto.createHash(exports.DIGEST);
    hasher.update(message.toString());
    var digest = hasher.digest();
    digest = new bali.Binary(digest);
    return digest;
};


/**
 * This function returns a reference citation for the specified document. The citation is
 * a Bali reference containing an encoded Bali catalog that includes the protocol version,
 * document tag and version number, and a digital digest of the document. It can be used
 * to retrieve the document from the Bali Cloud Environment™ and verify that the retrieved
 * document has not be modified since it was cited.
 * 
 * @param {Tag} tag The unique tag for the document.
 * @param {Version} version The current version of the document.
 * @param {String|Document} document The document to be cited.
 * @returns {Reference} A Bali reference citation for the document.
 */
exports.cite = function(tag, version, document) {
    var encodedDigest = bali.Template.NONE;
    if (document) {
        encodedDigest = exports.digest(document);
    }
    var citation = new bali.Catalog();
    citation.setValue('$protocol', exports.PROTOCOL);
    citation.setValue('$tag', tag);
    citation.setValue('$version', version);
    citation.setValue('$digest', encodedDigest);
    return citation;
};


/**
 * This function creates a new document citation with a new unique tag. The digest for
 * the citation is set to Template.NONE since there is no document yet to cite.
 * 
 * @returns {Catalog} A new document citation.
 */
exports.citationFromScratch = function() {
    var protocol = exports.PROTOCOL;
    var tag = new bali.Tag();
    var version = new bali.Version('v1');
    var digest = bali.Template.NONE;
    var citation = new bali.Catalog();
    citation.setValue('$protocol', protocol);
    citation.setValue('$tag', tag);
    citation.setValue('$version', version);
    citation.setValue('$digest', digest);
    return citation;
};


/**
 * This function creates a document citation based on the specified Bali source code.
 * 
 * @param {String} source The Bali source code for the document citation. 
 * @returns {Catalog} The resulting document citation.
 */
exports.citationFromSource = function(source) {
    var document = bali.parser.parseDocument(source);
    var protocol = document.getValue('$protocol');
    var tag = document.getValue('$tag');
    var version = document.getValue('$version');
    var digest = document.getValue('$digest');
    var citation = new bali.Catalog();
    citation.setValue('$protocol', protocol);
    citation.setValue('$tag', tag);
    citation.setValue('$version', version);
    citation.setValue('$digest', digest);
    return citation;
};


/**
 * This function creates a document citation based on the specified document reference.
 * The attributes for the document citation are encoded in the body of the document
 * reference.
 * 
 * @param {Reference} reference The Bali reference containing the citation attributes.
 * @returns {Catalog} The resulting document citation.
 */
exports.citationFromReference = function(reference) {
    reference = reference.toSource();
    var source = reference.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var citation = bali.parser.parseComponent(source);
    return citation;
};


/**
 * This function creates a document reference based on the specified document citation.
 * The attributes for the document citation are encoded in the body of the new document
 * reference.
 * 
 * @param {Catalog} citation The document citation containing the citation attributes.
 * @returns {Reference} The resulting Bali reference containing the citation attributes.
 */
exports.referenceFromCitation = function(citation) {
    var reference = '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>';
    reference = reference.replace(/%protocol/, citation.getValue('$protocol'));
    reference = reference.replace(/%tag/, citation.getValue('$tag'));
    reference = reference.replace(/%version/, citation.getValue('$version'));
    reference = reference.replace(/%digest/, citation.getValue('$digest').toSource().replace(/\s+/g, ''));
    reference = new bali.Reference(reference);
    return reference;
};
