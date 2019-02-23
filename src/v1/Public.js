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
 * This module defines a library of cryptographic functions that involve the use of a
 * public key. The public key is associated with a private key that is maintained
 * within a hardware security module (HSM).
 */
const crypto = require('crypto');
const ec_pem = require('ec-pem');
const bali = require('bali-component-framework');


// ALGORITHMS FOR THIS VERSION OF THE PROTOCOL

exports.PROTOCOL = 'v1';
exports.CURVE = 'prime256v1';  // AKA 'secp256r1'
exports.DIGEST = 'sha512';
exports.SIGNATURE = 'sha512';
exports.CIPHER = 'aes-256-gcm';

exports.protocol = bali.parse(exports.PROTOCOL);

// This private constant sets the POSIX end of line character
const EOL = '\n';



// FUNCTIONS

/**
 * This function returns a list of notary protocol versions supported by this module.
 * 
 * @returns {List} A list of notary protocol versions supported by this module.
 */
exports.versions = function() {
    const versions = bali.list([exports.protocol]);
    return versions;
};


/**
 * This function checks to make sure that the specified document was created using a
 * supported version of the notary protocol.  If not, an exception is thrown.
 * 
 * @param {String} module The symbol for the module that called this function.
 * @param {String} procedure The symbol for the procedure that called this function.
 * @param {Catalog} document The document to be checked.
 * @throws {Exception} The specified document does not contain a supported version of the
 * notary protocol.
 */
exports.check = function(module, procedure, document) {
    const protocol = document.getValue('$protocol');
    if (!exports.versions().containsItem(protocol)) {
        throw bali.exception({
            $module: module,
            $procedure: procedure,
            $exception: '$unsupportedProtocol',
            $protocol: protocol,
            $document: document,
            $message: '"The notary protocol version for the document is not supported."'
        });
    }
};


/**
 * This function encodes the specified attributes in a canonical way so that the resulting
 * string can be digitally signed and verified.
 * 
 * @param {Catalog} previous An optional document citation to the previous version of the
 * notarized document for the component.
 * @param {Component} component The component to be notarized.
 * @param {Catalog} citation A document citation to the notary certificate that may be used
 * to verify the resulting notarized document for this component.
 * @returns {String} The encoded string for the specified document attributes.
 */
exports.encode = function(previous, component, citation) {
    var encoded = '';
    if (previous) encoded += previous + EOL;
    encoded += component + EOL;
    encoded += citation;
    return encoded;
};


/**
 * This function returns a cryptographically secure base 32 encoded digital digest of
 * the specified message string. The digest is a Bali binary string and will always be
 * the same for the same message.
 * 
 * @param {String} message The message to be digested.
 * @returns {Binary} A base 32 encoded digital digest of the message.
 */
exports.digest = function(message) {
    const hasher = crypto.createHash(exports.DIGEST);
    hasher.update(message.toString());  // force it to a string if it isn't already
    const digest = hasher.digest();
    const binary = bali.binary(digest);
    return binary;
};


/**
 * This function uses the specified base 32 encoded public key to determine whether
 * or not the specified base 32 encoded digital signature was generated using the
 * corresponding private key on the specified message.
 * 
 * @param {String} message The digitally signed message.
 * @param {Binary} publicKey The base 32 encoded public key.
 * @param {Binary} signature The digital signature generated using the private key.
 * @returns {Boolean} Whether or not the digital signature is valid.
 */
exports.verify = function(message, publicKey, signature) {
    signature = signature.getValue();
    publicKey = publicKey.getValue();
    const curve = crypto.createECDH(exports.CURVE);
    curve.setPublicKey(publicKey);
    const pem = ec_pem(curve, exports.CURVE);
    const verifier = crypto.createVerify(exports.SIGNATURE);
    verifier.update(message.toString());
    return verifier.verify(pem.encodePublicKey(), signature);
};


/**
 * This function uses the specified base 32 encoded public key to encrypt the specified
 * plaintext message. The result is an authenticated encrypted message (AEM) that can
 * only be decrypted using the associated private key.
 * 
 * @param {String} message The plaintext message to be encrypted.
 * @param {Binary} publicKey The base 32 encoded public key to use for encryption.
 * @returns {Catalog} An authenticated encrypted message.
 */
exports.encrypt = function(message, publicKey) {
    publicKey = publicKey.getValue();
    // generate and encrypt a 32-byte symmetric key
    const curve = crypto.createECDH(exports.CURVE);
    curve.generateKeys();
    const seed = curve.getPublicKey();  // use the new public key as the seed
    const symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

    // encrypt the message using the symmetric key
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(exports.CIPHER, symmetricKey, iv);
    var ciphertext = cipher.update(message.toString(), 'utf8');  // force it to a string if it isn't already
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const auth = cipher.getAuthTag();

    // construct the authenticated encrypted message (AEM)
    const aem = bali.catalog({
        $protocol: exports.protocol,
        $seed: bali.binary(seed),
        $iv: bali.binary(iv),
        $auth: bali.binary(auth),
        $ciphertext: bali.binary(ciphertext)
    });

    return aem;
};


/**
 * This function creates a new document citation using the specified attributes.
 * 
 * @param {Tag} tag The unique tag for the cited document.
 * @param {Version} version The version of the cited document, default is 'v1'.
 * @param {Binary} digest The (optional) base 32 encoded digest of the cited document.
 * @returns {Catalog} A new document citation.
 */
exports.citation = function(tag, version, digest) {
    const protocol = exports.protocol;
    tag = tag || bali.tag();
    version = version || bali.version();
    const citation = bali.catalog({
        $protocol: protocol,
        $tag: tag,
        $version: version
    });
    if (digest) citation.setValue('$digest', digest);
    return citation;
};
