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


var V1 = {

    PROTOCOL: 'v1',
    CURVE: 'secp521r1',
    DIGEST: 'sha512',
    SIGNATURE: 'ecdsa-with-SHA1',
    CIPHER: 'aes-256-gcm',

    REFERENCE_TEMPLATE: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>',

    CITATION_TEMPLATE:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $digest: %digest\n' +
        ']\n',

    CERTIFICATE_TEMPLATE:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $publicKey: %publicKey\n' +
        ']\n',

    AEM_TEMPLATE:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $iv: %iv\n' +
        '    $tag: %tag\n' +
        '    $seed: %seed\n' +
        '    $ciphertext: %ciphertext\n' +
        ']\n',

    digest: function(message) {
        var hasher = crypto.createHash(V1.DIGEST);
        hasher.update(message);
        var digest = hasher.digest();
        var encodedDigest = "'" + codex.base32Encode(digest).replace(/\s+/g, '') + "'";
        return encodedDigest;
    },

    cite: function(tag, version, document) {
        var encodedDigest = 'none';
        if (document) {
            encodedDigest = V1.digest(document);
        }
        var reference = V1.REFERENCE_TEMPLATE;
        reference = reference.replace(/%protocol/, V1.PROTOCOL);
        reference = reference.replace(/%tag/, tag);
        reference = reference.replace(/%version/, version);
        reference = reference.replace(/%digest/, encodedDigest);
        return reference;
    },

    bufferToEncoded: function(buffer, padding) {
        if (!padding) padding = '';
        var base32 = codex.base32Encode(buffer, padding + '    ');
        var encoded = "'" + base32 + "\n" + padding + "'";  // add in the "'"s
        return encoded;
    },

    encodedToBuffer: function(encoded) {
        var base32 = encoded.slice(1, -1);  // remove the "'"s
        buffer = codex.base32Decode(base32);
        return buffer;
    }

};
exports.V1 = V1;
