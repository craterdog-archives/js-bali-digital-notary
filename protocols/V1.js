/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
var codex = require('bali-document-notation/utilities/EncodingUtilities');
var crypto = require('crypto');


exports.PROTOCOL = 'v1';
exports.CURVE = 'secp521r1';
exports.DIGEST = 'sha512';
exports.SIGNATURE = 'ecdsa-with-SHA1';
exports.CIPHER = 'aes-256-gcm';

exports.REFERENCE_TEMPLATE = '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>';

exports.CITATION_TEMPLATE =
    '[\n' +
    '    $protocol: %protocol\n' +
    '    $tag: %tag\n' +
    '    $version: %version\n' +
    '    $digest: %digest\n' +
    ']\n';

exports.CERTIFICATE_TEMPLATE =
    '[\n' +
    '    $protocol: %protocol\n' +
    '    $tag: %tag\n' +
    '    $version: %version\n' +
    '    $publicKey: %publicKey\n' +
    ']\n';

exports.AEM_TEMPLATE =
    '[\n' +
    '    $protocol: %protocol\n' +
    '    $iv: %iv\n' +
    '    $auth: %auth\n' +
    '    $seed: %seed\n' +
    '    $ciphertext: %ciphertext\n' +
    ']\n';

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
    var reference = exports.REFERENCE_TEMPLATE;
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
    buffer = codex.base32Decode(base32);
    return buffer;
};
