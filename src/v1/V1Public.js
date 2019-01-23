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


// FUNCTIONS

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
    const binary = new bali.Binary(digest);
    return binary;
};


/**
 * This function returns a document citation for the specified document. The citation is
 * a Bali catalog containing the security protocol version, document tag and version number,
 * and a digital digest of the document string. It can be used to verify that when the
 * document is later retrieved it has not be modified since it was cited.
 * 
 * @param {Tag} tag The unique tag for the document.
 * @param {Version} version The current version of the document.
 * @param {String} document The document to be cited.
 * @returns {Catalog} The document citation for the document.
 */
exports.cite = function(tag, version, document) {
    document = document.toString();  // force it to be a string
    const digest = exports.digest(document.toString());  // force it to be a string if it isn't
    const citation = exports.citationFromAttributes(tag, version, digest);
    return citation;
};


/**
 * This function uses the specified base 32 encoded public key to determine whether
 * or not the specified base 32 encoded digital signature was generated using the
 * corresponding private key on the specified message.
 * 
 * @param {Binary} publicKey The base 32 encoded public key.
 * @param {String} message The digitally signed message.
 * @param {Binary} signature The digital signature generated using the private key.
 * @returns {Boolean} Whether or not the digital signature is valid.
 */
exports.verify = function(publicKey, message, signature) {
    signature = signature.value;
    message = message.toString();  // force it to be a string
    publicKey = publicKey.value;
    const curve = crypto.createECDH(exports.CURVE);
    curve.setPublicKey(publicKey);
    const pem = ec_pem(curve, exports.CURVE);
    const verifier = crypto.createVerify(exports.SIGNATURE);
    verifier.update(message);
    return verifier.verify(pem.encodePublicKey(), signature);
};


/**
 * This function uses the specified base 32 encoded public key to encrypt the specified
 * plaintext message. The result is an authenticated encrypted message (AEM) that can
 * only be decrypted using the associated private key.
 * 
 * @param {Binary} publicKey The base 32 encoded public key to use for encryption.
 * @param {String} message The plaintext message to be encrypted.
 * @returns {Catalog} An authenticated encrypted message.
 */
exports.encrypt = function(publicKey, message) {
    publicKey = publicKey.value;
    message = message.toString();  // force it to be a string
    // generate and encrypt a 32-byte symmetric key
    const curve = crypto.createECDH(exports.CURVE);
    curve.generateKeys();
    const seed = curve.getPublicKey();  // use the new public key as the seed
    const symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

    // encrypt the message using the symmetric key
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(exports.CIPHER, symmetricKey, iv);
    var ciphertext = cipher.update(message, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const auth = cipher.getAuthTag();

    // construct the authenticated encrypted message (AEM)
    const aem = new bali.Catalog();
    aem.setValue('$protocol', bali.Version.fromLiteral(exports.PROTOCOL));
    aem.setValue('$iv', new bali.Binary(iv));
    aem.setValue('$auth', new bali.Binary(auth));
    aem.setValue('$seed', new bali.Binary(seed));
    aem.setValue('$ciphertext', new bali.Binary(ciphertext));

    return aem;
};


/**
 * This function creates a new document citation using the specified attributes. If no
 * digest is specified, the digest value is set to Filter.NONE.
 * 
 * @param {Tag} tag The unique tag for the cited document.
 * @param {Version} version The version of the cited document, default is 'v1'.
 * @param {Binary} digest The (optional) base 32 encoded digest of the cited document.
 * @returns {Catalog} A new document citation.
 */
exports.citationFromAttributes = function(tag, version, digest) {
    const protocol = bali.Version.fromLiteral(exports.PROTOCOL);
    tag = tag || new bali.Tag();
    version = version || bali.Version.fromLiteral('v1');
    digest = digest || bali.Pattern.fromLiteral('none');
    const citation = new bali.Catalog();
    citation.setValue('$protocol', protocol);
    citation.setValue('$tag', tag);
    citation.setValue('$version', version);
    citation.setValue('$digest', digest);
    return citation;
};


/**
 * This function creates a document citation based on the specified Bali Document Notation™.
 * 
 * @param {String} source The Bali Document Notation™ for the document citation. 
 * @returns {Catalog} The resulting document citation.
 */
exports.citationFromSource = function(source) {
    const citation = bali.parse(source);
    const protocol = citation.getValue('$protocol');
    if (exports.PROTOCOL !== protocol.toString()) {
        const attributes = bali.Catalog.fromSequential({
            $exception: '$unsupportedProtocol',
            $protocol: protocol,
            $message: 'The protocol for the citation is not supported.'
        });
        throw new bali.Exception(attributes);
    }
    return citation;
};


/**
 * This function creates a document citation based on the specified document reference.
 * The attributes for the document citation are encoded in the body of the document
 * reference using the Bali Document Notation™.
 * 
 * @param {Reference} reference The Bali reference containing the encoded document citation.
 * @returns {Catalog} The decoded document citation.
 */
exports.citationFromReference = function(reference) {
    reference = reference.toString();
    const source = reference.slice(6, -1);  // remove '<bali:' and '>' wrapper
    const citation = bali.parse(source);
    const protocol = citation.getValue('$protocol');
    if (exports.PROTOCOL !== protocol.toString()) {
        const attributes = bali.Catalog.fromSequential({
            $exception: '$unsupportedProtocol',
            $protocol: protocol,
            $message: 'The protocol for the citation is not supported.'
        });
        throw new bali.Exception(attributes);
    }
    return citation;
};


/**
 * This function creates a document reference based on the specified document citation.
 * The attributes for the document citation are encoded in the body of the new document
 * reference using the Bali Document Notation™.
 * 
 * @param {Catalog} citation The document citation containing the citation attributes.
 * @returns {Reference} The resulting Bali reference containing the citation attributes.
 */
exports.referenceFromCitation = function(citation) {
    var reference = '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>';
    reference = reference.replace(/%protocol/, citation.getValue('$protocol'));
    reference = reference.replace(/%tag/, citation.getValue('$tag'));
    reference = reference.replace(/%version/, citation.getValue('$version'));
    reference = reference.replace(/%digest/, citation.getValue('$digest').toString().replace(/\s+/g, ''));
    reference = bali.Reference.fromLiteral(reference);
    return reference;
};
