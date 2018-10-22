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


// ALGORITHMS AND PROTOCOLS

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
function digest(message) {
    var hasher = crypto.createHash(exports.DIGEST);
    hasher.update(message.toString());
    var digest = hasher.digest();
    var encodedDigest = "'" + bali.codex.base32Encode(digest) + "'";
    encodedDigest = new bali.Binary(encodedDigest);
    return encodedDigest;
}
exports.digest = digest;


/**
 * This function returns a reference citation for the specified document. The citation is
 * a Bali reference containing an encoded Bali catalog that includes the protocol version,
 * document tag and version number, and a digital digest of the document. It can be used
 * to retrieve the document from the Bali Cloud Environment™ and verify that the retrieved
 * document has not be modified since it was cited.
 * 
 * @param {Tag} tag The unique tag for the document.
 * @param {Version} version The current version of the document.
 * @param {Document} document The document to be cited.
 * @returns {Reference} A Bali reference citation for the document.
 */
function cite(tag, version, document) {
    var encodedDigest = bali.Template.NONE;
    if (document) {
        encodedDigest = digest(document);
    }
    var citation = new Citation(exports.PROTOCOL, tag, version, encodedDigest);
    return citation;
}
exports.cite = cite;


function Citation(protocol, tag, version, digest) {
    this.protocol = protocol;
    this.tag = tag;
    this.version = version;
    this.digest = digest;
    return this;
}
Citation.prototype.constructor = Citation;
exports.Citation = Citation;


Citation.fromScratch = function() {
    var protocol = exports.PROTOCOL;
    var tag = new bali.Tag();
    var version = new bali.Version('v1');
    var digest = bali.Template.NONE;
    var citation = new Citation(protocol, tag, version, digest);
    return citation;
};


Citation.fromSource = function(source) {
    var document = bali.parser.parseDocument(source);
    var protocol = document.getValue('$protocol');
    var tag = document.getValue('$tag');
    var version = document.getValue('$version');
    var digest = document.getValue('$digest');
    var citation = new Citation(protocol, tag, version, digest);
    return citation;
};


Citation.fromReference = function(reference) {
    reference = reference.toSource();
    var source = reference.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var catalog = bali.parser.parseComponent(source);
    var protocol = catalog.getValue('$protocol');
    var tag = catalog.getValue('$tag');
    var version = catalog.getValue('$version');
    var digest = catalog.getValue('$digest');
    var citation = new Citation(protocol, tag, version, digest);
    return citation;
};


Citation.prototype.toString = function() {
    var source = this.toSource();
    return source;
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


Citation.prototype.toReference = function() {
    var reference = '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>';
    reference = reference.replace(/%protocol/, this.protocol);
    reference = reference.replace(/%tag/, this.tag);
    reference = reference.replace(/%version/, this.version);
    reference = reference.replace(/%digest/, this.digest.toSource().replace(/\s+/g, ''));
    reference = new bali.Reference(reference);
    return reference;
};
