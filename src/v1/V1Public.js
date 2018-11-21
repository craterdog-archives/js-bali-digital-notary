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
var crypto = require('crypto');
var ec_pem = require('ec-pem');
var bali = require('bali-component-framework');


// ALGORITHMS FOR THIS VERSION OF THE PROTOCOL

exports.PROTOCOL = 'v1';
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
 * @param {String|NotarizedDocument} document The document to be cited.
 * @returns {Reference} A Bali reference citation for the document.
 */
exports.cite = function(tag, version, document) {
    var digest = exports.digest(document);
    var citation = exports.citationFromAttributes(tag, version, digest);
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
    signature = signature.getBuffer();
    publicKey = publicKey.getBuffer();
    var curve = crypto.createECDH(exports.CURVE);
    curve.setPublicKey(publicKey);
    var pem = ec_pem(curve, exports.CURVE);
    var verifier = crypto.createVerify(exports.SIGNATURE);
    verifier.update(message);
    return verifier.verify(pem.encodePublicKey(), signature);
};


/**
 * This function uses the specified base 32 encoded public key to encrypt the specified
 * plaintext message. The result is an authenticated encrypted message (AEM) object that
 * can only be decrypted using the associated private key.
 * 
 * @param {Binary} publicKey The base 32 encoded public key to use for encryption.
 * @param {String} message The plaintext message to be encrypted.
 * @returns {Catalog} An authenticated encrypted message object.
 */
exports.encrypt = function(publicKey, message) {
    publicKey = publicKey.getBuffer();
    // generate and encrypt a 32-byte symmetric key
    var curve = crypto.createECDH(exports.CURVE);
    curve.generateKeys();
    var seed = curve.getPublicKey();  // use the new public key as the seed
    var symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

    // encrypt the message using the symmetric key
    var iv = crypto.randomBytes(12);
    var cipher = crypto.createCipheriv(exports.CIPHER, symmetricKey, iv);
    var ciphertext = cipher.update(message, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    var auth = cipher.getAuthTag();

    // construct the authenticated encrypted message (AEM)
    var aem = new bali.Catalog();
    aem.setValue('$protocol', new bali.Version(exports.PROTOCOL));
    aem.setValue('$iv', new bali.Binary(iv));
    aem.setValue('$auth', new bali.Binary(auth));
    aem.setValue('$seed', new bali.Binary(seed));
    aem.setValue('$ciphertext', new bali.Binary(ciphertext));

    return aem;
};


/**
 * This function creates a new document citation using the specified attributes. If no
 * digest is specified, the digest value is set to Template.NONE.
 * 
 * @param {Tag} tag The unique tag for the cited document.
 * @param {Version} version The version of the cited document, default is 'v1'.
 * @param {Binary} digest The (optional) base 32 encoded digest of the cited document.
 * @returns {Catalog} A new document citation.
 */
exports.citationFromAttributes = function(tag, version, digest) {
    var protocol = new bali.Version(exports.PROTOCOL);
    tag = tag || new bali.Tag();
    version = version || new bali.Version('v1');
    digest = digest || bali.Template.NONE;
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
    if (exports.PROTOCOL !== protocol.toString()) {
        throw new Error('NOTARY: The protocol for the citation is not supported: ' + protocol);
    }
    var tag = document.getValue('$tag');
    var version = document.getValue('$version');
    var digest = document.getValue('$digest');
    var citation = exports.citationFromAttributes(tag, version, digest);
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
    reference = reference.toString();
    var source = reference.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var citation = bali.parser.parseDocument(source);
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
    reference = reference.replace(/%digest/, citation.getValue('$digest').toString().replace(/\s+/g, ''));
    reference = new bali.Reference(reference);
    return reference;
};
