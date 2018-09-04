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
 * This module defines a library of constants and functions that needed by the version
 * one (V1) security protocol implementation for the Bali Cloud Environment™.
 */
var codex = require('bali-document-notation/utilities/EncodingUtilities');
var crypto = require('crypto');


// ALGORITHMS AND PROTOCOLS

exports.PROTOCOL = 'v1';
exports.CURVE = 'secp521r1';
exports.DIGEST = 'sha512';
exports.SIGNATURE = 'ecdsa-with-SHA1';
exports.CIPHER = 'aes-256-gcm';


// FUNCTIONS

exports.digest = function(message) {
    var hasher = crypto.createHash(exports.DIGEST);
    hasher.update(message);
    var digest = hasher.digest();
    var encodedDigest = "'" + codex.base32Encode(digest).replace(/\s+/g, '') + "'";
    return encodedDigest;
};

exports.cite = function(tag, version, document) {
    var encodedDigest = 'none';
    if (document) {
        encodedDigest = exports.digest(document);
    }
    var reference = '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>';
    reference = reference.replace(/%protocol/, exports.PROTOCOL);
    reference = reference.replace(/%tag/, tag);
    reference = reference.replace(/%version/, version);
    reference = reference.replace(/%digest/, encodedDigest);
    return reference;
};

exports.bufferToEncoded = function(buffer, padding) {
    if (!padding) padding = '';
    var base32 = codex.base32Encode(buffer, padding + '    ');
    var encoded = "'" + base32 + "\n" + padding + "'";  // add in the "'"s
    return encoded;
};

exports.encodedToBuffer = function(encoded) {
    var base32 = encoded.slice(1, -1);  // remove the "'"s
    var buffer = codex.base32Decode(base32);
    return buffer;
};
