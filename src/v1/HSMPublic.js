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
const debug = false;  // set to true for error logging
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


// FUNCTIONS

/**
 * This function returns a cryptographically secure base 32 encoded digital digest of
 * the specified component. The digest is a Bali binary string and will always be
 * the same for the same component.
 * 
 * @param {Component} component The component to be digested.
 * @returns {Binary} A base 32 encoded digital digest of the component.
 */
exports.digest = function(component) {
    try {
        const string = component.toString();
        const hasher = crypto.createHash(exports.DIGEST);
        hasher.update(string);
        const digest = hasher.digest();
        const binary = bali.binary(digest);
        return binary;
    } catch (cause) {
        const exception = bali.exception({
            $module: '$HSMPublic',
            $function: '$digest',
            $exception: '$unexpected',
            $string: bali.text(string),
            $message: bali.text('An unexpected error occurred while attempting to generate a digest.')
        }, cause);
        if (debug) console.error(exception.toString());
        throw exception;
    }
};


/**
 * This function uses the specified base 32 encoded public key to determine whether
 * or not the specified base 32 encoded digital signature was generated using the
 * corresponding private key on the specified component.
 * 
 * @param {Component} component The digitally signed component.
 * @param {Binary} publicKey The base 32 encoded public key.
 * @param {Binary} signature The digital signature generated using the private key.
 * @returns {Boolean} Whether or not the digital signature is valid.
 */
exports.verify = function(component, publicKey, signature) {
    try {
        const string = component.toString();
        signature = signature.getValue();
        publicKey = publicKey.getValue();
        const curve = crypto.createECDH(exports.CURVE);
        curve.setPublicKey(publicKey);
        const pem = ec_pem(curve, exports.CURVE);
        const verifier = crypto.createVerify(exports.SIGNATURE);
        verifier.update(string);
        return verifier.verify(pem.encodePublicKey(), signature);
    } catch (cause) {
        const exception = bali.exception({
            $module: '$HSMPublic',
            $function: '$verify',
            $exception: '$unexpected',
            $string: bali.text(string),
            $message: bali.text('An unexpected error occurred while attempting to verify a signature.')
        }, cause);
        if (debug) console.error(exception.toString());
        throw exception;
    }
};


/**
 * This function uses the specified base 32 encoded public key to encrypt the specified
 * component. The result is an authenticated encrypted message (AEM) that can only be
 * decrypted using the associated private key.
 * 
 * @param {Component} component The component to be encrypted.
 * @param {Binary} publicKey The base 32 encoded public key to use for encryption.
 * @returns {Catalog} An authenticated encrypted message.
 */
exports.encrypt = function(component, publicKey) {
    try {
        // convert the component to a string and public key to bytes
        const string = component.toString();
        const bytes = publicKey.getValue();

        // generate and encrypt a 32-byte symmetric key
        const curve = crypto.createECDH(exports.CURVE);
        curve.generateKeys();
        const seed = curve.getPublicKey();  // use the new public key as the seed
        const symmetricKey = curve.computeSecret(bytes).slice(0, 32);  // take only first 32 bytes

        // encrypt the string using the symmetric key
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(exports.CIPHER, symmetricKey, iv);
        var ciphertext = cipher.update(string, 'utf8');
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);
        const auth = cipher.getAuthTag();

        // construct the authenticated encrypted message (AEM)
        const aem = bali.catalog({
            $protocol: exports.protocol,
            $timestamp: bali.moment(),  // now
            $seed: bali.binary(seed),
            $iv: bali.binary(iv),
            $auth: bali.binary(auth),
            $ciphertext: bali.binary(ciphertext)
        });

        return aem;
    } catch (cause) {
        // create a digest of the component to maintain privacy
        const hasher = crypto.createHash(exports.DIGEST);
        hasher.update(component.toString());
        const digest = bali.binary(hasher.digest());
        const exception = bali.exception({
            $module: '$HSMPublic',
            $function: '$encrypt',
            $exception: '$unexpected',
            $digest: digest,
            $publicKey: publicKey,
            $message: bali.text('An unexpected error occurred while attempting to encrypt a component.')
        }, cause);
        if (debug) console.error(exception.toString());
        throw exception;
    }
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
    return bali.catalog({
        $protocol: exports.protocol,
        $timestamp: bali.moment(),  // now
        $tag: tag,
        $version: version,
        $digest: digest
    });
};
