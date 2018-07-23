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
var URL = require('url').URL;
var crypto = require('crypto');
var ec_pem = require('ec-pem');
var bali = require('bali-language/BaliLanguage');
var codex = require('bali-utilities/EncodingUtilities');


// source templates for a notary key
var V1_KEY =
        '[\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $protocol: %protocol\n' +
        '    $publicKey: %publicKey\n' +
        '    $privateKey: %privateKey\n' +
        '    $previous: %previous\n' +
        '    $citation: %citation\n' +
        ']';

/**
 * This constructor creates a notary key that can be used to digitally notarize
 * Bali documents. If a Bali document containing the notary key definition is
 * passed into the constructor, the key definition will be used to construct the
 * notary key. Otherwise, a new notary key and its associated certificate will be
 * generated. The associated notary certificate may then be retrieved from
 * 'this.certificate'. If a protocol version string is passed into the constructor, that
 * version of the Bali Notary Protocol will be used to construct the notary key
 * and certificate. Otherwise, a new 'v1' notary key and certificate will be
 * created.
 * 
 * @constructor
 * @param {Document|String} documentOrProtocol An optional Bali document containing
 * the notary key definition or the protocol version to be used to generate a new
 * notary key and associated certificate.
 * @returns {NotaryKey} The resulting notary key.
 */
function NotaryKey(documentOrProtocol) {
    // validate the argument
    var document;
    var protocol;
    if (documentOrProtocol) {
        if (bali.isVersion(documentOrProtocol)) {
            protocol = documentOrProtocol;
        } else if (bali.isDocument(documentOrProtocol)) {
            document = documentOrProtocol;
            protocol = bali.getValueForKey(document, '$protocol').toString();
            if (!bali.isVersion(protocol)) {
                throw new Error('NOTARY: The constructor was passed a document with an invalid protocol version: ' + protocol);
            }
        } else {
            throw new Error('NOTARY: The constructor was passed an invalid argument: ' + documentOrProtocol);
        }
    } else {
        protocol = 'v1';  // NOTE: this default value CANNOT change later on!
    }

    // construct the correct protocol version of the notary key
    switch(protocol) {
        case 'v1':
            if (document) {
                // extract the unique tag and version number for this notary key
                this.tag = bali.getValueForKey(document, '$tag').toString();
                this.version = bali.getValueForKey(document, '$version').toString();

                // extract the key pair
                this.protocol = protocol;
                var binary = bali.getValueForKey(document, '$publicKey').toString();
                this.publicKey = binaryToBuffer(binary);
                binary = bali.getValueForKey(document, '$privateKey').toString();
                this.privateKey = binaryToBuffer(binary);
                var previous = bali.getValueForKey(document, '$previous');
                if (previous !== 'none') {
                    this.previous = previous.toString();
                }

            } else {
                // generate a unique tag and version number for this notary key
                this.tag = bali.tag();
                this.version = 'v1';  // the initial version of the notary key

                // generate a new notary key
                this.protocol = protocol;
                var keypair = generateV1();
                this.publicKey = keypair.publicKey;
                this.privateKey = keypair.privateKey;

            }

            // construct a temporary citation with no hash for the certificate
            var reference = V1_REFERENCE.replace(/%tag/, this.tag);
            this.citation = reference.replace(/%version/, this.version);

            // create the certificate
            var source = V1_CERTIFICATE.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%publicKey/, bufferToBinary(this.publicKey));
            if (this.previous) {
                source = this.previous + '\n' + source;
            }
            document = bali.parseDocument(source);
            // TODO: how do we preserve previous notary seals???
            this.notarizeDocument(document);

            // now construct the full citation including the hash
            this.citation = new exports.DocumentCitation(this.citation, document, protocol);

            // cache the certificate
            this.certificate = new exports.NotaryCertificate(document);
            return this;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
}
NotaryKey.prototype.constructor = NotaryKey;
exports.NotaryKey = NotaryKey;


/**
 * This method exports the notary key definition as Bali document source.
 * 
 * @returns {String} A string containing the resulting Bali document.
 */
NotaryKey.prototype.toString = function() {
    switch(this.protocol) {
        case 'v1':
            var source = V1_KEY.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%publicKey/, bufferToBinary(this.publicKey));
            source = source.replace(/%privateKey/, bufferToBinary(this.privateKey));
            if (this.previous) {
                source = source.replace(/%previous/, this.previous);
            } else {
                source = source.replace(/%previous/, 'none');
            }
            source = source.replace(/%citation/, this.citation);
            return source;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


/**
 * This method regenerates a notary key and associated notary certificate. It
 * uses the old notary key to notarize the new notary certificate to prove its
 * place in the notary certificate chain.
 * 
 * @returns {NotaryCertificate} The new notary certificate.
 */
NotaryKey.prototype.regenerateKey = function() {
    switch(this.protocol) {
        case 'v1':
            var nextVersion = getNextVersion(this.version);

            // generate a new notary key
            var keypair = generateV1();

            // construct a temporary citation for the certificate
            var reference = V1_REFERENCE.replace(/%tag/, this.tag);
            var citation = reference.replace(/%version/, nextVersion);

            // create the certificate
            var source = V1_CERTIFICATE.replace(/%tag/, this.tag);
            source = source.replace(/%version/, nextVersion);
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%publicKey/, bufferToBinary(keypair.publicKey));
            source = this.citation + '\n' + source;  // now it's a citation to the previous certificate
            var document = bali.parseDocument(source);

            // notarize it with the old key
            this.notarizeDocument(document);

            // notarize it with the new key
            this.version = nextVersion;
            this.publicKey = keypair.publicKey;
            this.privateKey = keypair.privateKey;
            this.previous = this.citation;
            this.citation = citation;
            this.notarizeDocument(document);

            // now construct the full citation including hash
            this.citation = new exports.DocumentCitation(citation, document, this.protocol);

            // cache the certificate
            this.certificate = new exports.NotaryCertificate(document);
            return this.certificate;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


/**
 * This method digitally notarizes a Bali document using this notary key. The resulting
 * notary seal is appended to the document and can be validated using the
 * <code>documentIsValid()</code> method on the associated notary certificate.
 * 
 * @param {Document} document The Bali document to be notarized.
 */
NotaryKey.prototype.notarizeDocument = function(document) {
    // validate the argument
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The constructor only requires a valid Bali document: ' + document);
    }
    switch(this.protocol) {
        case 'v1':
            // prepare the document source
            var source = document.toString();
            source += this.citation;  // NOTE: the citation must be included in the signed source!

            // generate the notarization signature
            var signature = "'" + signV1(this.privateKey, source) + "\n'";

            // append the notary seal to the document
            bali.addSeal(document, this.citation, signature);
            break;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


/**
 * This method decrypts an authenticated encrypted message generated using the notary
 * certificate associated with this notary key. The notary certificate generated and
 * encrypted a random secret key that was used to encrypt the original message. The
 * decrypted message is returned from this method.
 * 
 * @param {Object} message The authenticated encrypted message.
 * @returns {String} The decrypted message.
 */
NotaryKey.prototype.decryptMessage = function(message) {
    switch(this.protocol) {
        case 'v1':
            var plaintext = decryptV1(this.privateKey, message);
            return plaintext;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


// source templates for a notary certificate
var V1_CERTIFICATE =
        '[\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $protocol: %protocol\n' +
        '    $publicKey: %publicKey\n' +
        ']';

/**
 * This constructor creates a notary certificate using a Bali document that contains the
 * notary certificate definition.
 * 
 * @constructor
 * @param {Document} document A Bali document containing the notary certificate definition.
 * @returns {NotaryCertificate} The notary certificate.
 */
function NotaryCertificate(document) {
    // validate the argument
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The constructor requires a valid Bali document: ' + document);
    }
    var protocol = bali.getValueForKey(document, '$protocol').toString();
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The constructor was passed a document with an invalid protocol version: ' + protocol);
    }

    switch(protocol) {
        case 'v1':
            // extract the unique tag and version for this notary certificate
            this.tag = bali.getValueForKey(document, '$tag').toString();
            this.version = bali.getValueForKey(document, '$version').toString();

            // extract the protocol version and public key for this notary certificate
            this.protocol = protocol;
            var binary = bali.getValueForKey(document, '$publicKey').toString();
            this.publicKey = binaryToBuffer(binary);
            var sealList = bali.getSeals(document);
            this.seals = [];
            for (var i = 0; i < sealList.length; i++) {
                var sealNode = sealList[i];
                var seal = {};
                seal.citation = bali.getCitation(sealNode).toString();
                seal.signature = bali.getSignature(sealNode).toString();
                this.seals.push(seal);
            }
            if (this.version !== 'v1') {
                this.previousCitation = bali.getPreviousCitation(document).toString();
            }
            break;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
    return this;
}
NotaryCertificate.prototype.constructor = NotaryCertificate;
exports.NotaryCertificate = NotaryCertificate;


/**
 * This method exports the notary certificate definition as Bali document source.
 * 
 * @returns {String} A string containing the corresponding Bali document source.
 */
NotaryCertificate.prototype.toString = function() {
    switch(this.protocol) {
        case 'v1':
            var source = V1_CERTIFICATE.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%protocol/, this.protocol);
            var base32 = codex.base32Encode(this.publicKey.toString('binary'), '        ');
            source = source.replace(/%publicKey/, "'" + base32 + "\n    '");
            for (var i = 0; i < this.seals.length; i++) {
                var seal = this.seals[i];
                source += '\n' + seal.citation;
                source += ' ' + seal.signature;
            }
            if (this.previousCitation) {
                source = this.previousCitation.toString() + '\n' + source;
            }
            return source;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


/**
 * This method validates a Bali document that was notarized using the
 * <code>notarizeDocument</code> method on the associated notary key. This notary
 * certificate is used to verify the notary seal that is appended to the Bali
 * document.
 * 
 * @param {Document} document The Bali document that was notarized.
 * @returns {Boolean} Whether or not the notary seal on the document is valid.
 */
NotaryCertificate.prototype.documentIsValid = function(document) {
    // validate the argument
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The constructor requires a Bali document: ' + document);
    }
    switch(this.protocol) {
        case 'v1':
            // separate the document from its last seal components
            var seal = bali.getSeal(document);
            var signature = bali.getSignature(seal);
            var citation = bali.getCitation(seal);
            document = bali.removeSeal(document);

            // calculate the hash of the document
            var source = document.toString();
            source += citation.toString();  // NOTE: the citation must be included in the signed source!

            // verify the signature using this notary certificate
            signature = signature.toString().slice(1, -1);  // remove the "'"s
            var isValid = verifyV1(this.publicKey, source, signature);
            return isValid;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


/**
 * This method generates a random symmetric key and uses it to encrypt a message.  The
 * symmetric key is then encrypted by the notary certificate and an authenticated
 * encrypted message is returned. The resulting authenticated encrypted message can
 * be decrypted using the <code>decryptMessage</code> method on the corresponding
 * notary key.
 * 
 * @param {String} message The message to be encrypted.
 * @returns {Object} The resulting authenticated encrypted message.
 */
NotaryCertificate.prototype.encryptMessage = function(message) {
    switch(this.protocol) {
        case 'v1':
            var ciphertext = encryptV1(this.publicKey, message);
            return ciphertext;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


// source templates for a document reference and citation
var V1_REFERENCE = '<bali:[$tag:%tag,$version:%version]>';
var V1_CITATION = '<bali:[$tag:%tag,$version:%version,$protocol:%protocol,$hash:%hash]>';

/**
 * This constructor creates a Bali document citation. It provides a reference to a
 * Bali document as well as either the actual Bali document or a SHA-512 cryptographic
 * hash of the Bali document. If anything in the contents of the document changes later
 * on, the hash value won't match and the changes can be detected.
 * 
 * @constructor
 * @param {String} reference The URL for the Bali document to be cited.
 * @param {Document|String} optionalDocument The actual Bali document to be cited.
 * @param {String} optionalProtocol The version of the Bali Notary Protocol™ that should be used to
 * create the document citation (e.g. 'v1', 'v1.3', 'v2', etc.).
 * @returns {DocumentCitation} The Bali document citation.
 */
function DocumentCitation(reference, optionalDocument, optionalProtocol) {
    // validate the arguments
    var document;
    var protocol;
    if (!bali.isReference(reference)) {
        throw new Error('NOTARY: The constructor requires a valid reference as the first argument: ' + reference);
    }
    var url = new URL(reference.slice(1, -1).replace(/#/, '%23'));
    var catalog = bali.parseComponent(url.pathname.replace(/%23/, '#'));
    if (bali.isDocument(optionalDocument)) {
        document = optionalDocument;
        if (bali.isVersion(optionalProtocol)) {
            protocol = optionalProtocol;
        } else {
            protocol = 'v1';  // NOTE: this default value CANNOT change later on!
        }
    } else {
        protocol = bali.getValueForKey(catalog, '$protocol');
        if (!bali.isVersion(protocol)) {
            throw new Error('NOTARY: The constructor received a reference with an invalid protocol version: ' + protocol);
        }
    }

    switch(protocol) {
        case 'v1':
            this.tag = bali.getValueForKey(catalog, '$tag').toString();
            this.version = bali.getValueForKey(catalog, '$version').toString();
            this.protocol = protocol;
            this.hash = "'" + digestV1(document.toString()) + "'";
            break;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
    return this;
}
DocumentCitation.prototype.constructor = DocumentCitation;
exports.DocumentCitation = DocumentCitation;


/**
 * This method exports the document citation as Bali document source.
 * value.
 * 
 * @returns {String} A string version of the document citation.
 */
DocumentCitation.prototype.toString = function() {
    switch(this.protocol) {
        case 'v1':
            var string = V1_CITATION.replace(/%tag/, this.tag.toString());
            string = string.replace(/%version/, this.version);
            string = string.replace(/%protocol/, this.protocol);
            string = string.replace(/%hash/, this.hash);
            return string;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


/**
 * This method determines whether or not the specified Bali document matches EXACTLY the
 * Bali document referenced by this citation.
 * 
 * @param {Document} document The Bali document parse tree to be validated.
 * @returns {Boolean} Whether or not the Bali document is valid.
 */
DocumentCitation.prototype.documentMatches = function(document) {
    // validate the argument
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The constructor requires a Bali document: ' + document);
    }
    switch(this.protocol) {
        case 'v1':
            var hash = digestV1(document.toString());
            return this.hash === "'" + hash + "'";
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


// PRIVATE FUNCTIONS

var CURVE = 'secp521r1';
var DIGEST = 'sha512';
var SIGNATURE = 'ecdsa-with-SHA1';
var CIPHER = 'aes-256-gcm';

function digestV1(message) {
    var hasher = crypto.createHash(DIGEST);
    hasher.update(message);
    var binary = hasher.digest().toString('binary');
    var digest = codex.base32Encode(binary).replace(/\s+/g, '');  // strip out any whitespace
    return digest;
}

function generateV1() {
    var curve = crypto.createECDH(CURVE);
    curve.generateKeys();
    return {
        privateKey: curve.getPrivateKey(),
        publicKey: curve.getPublicKey()
    };
}

function recreateV1(privateKey) {
    var curve = crypto.createECDH(CURVE);
    curve.setPrivateKey(privateKey);
    return {
        privateKey: curve.getPrivateKey(),
        publicKey: curve.getPublicKey()
    };
}

function signV1(privateKey, message) {
    var curve = crypto.createECDH(CURVE);
    curve.setPrivateKey(privateKey);
    var pem = ec_pem(curve, CURVE);
    var signer = crypto.createSign(SIGNATURE);
    signer.update(message);
    var binary = signer.sign(pem.encodePrivateKey(), 'binary');
    var signature = codex.base32Encode(binary, '    ');
    return signature;
}

function verifyV1(publicKey, message, signature) {
    var curve = crypto.createECDH(CURVE);
    curve.setPublicKey(publicKey);
    var pem = ec_pem(curve, CURVE);
    var verifier = crypto.createVerify(SIGNATURE);
    verifier.update(message);
    var binary = codex.base32Decode(signature);
    return verifier.verify(pem.encodePublicKey(), binary, 'binary');
}

function encryptV1(publicKey, plaintext) {
    // generate and encrypt a 32-byte symmetric key
    var curve = crypto.createECDH(CURVE);
    curve.generateKeys();
    var seed = curve.getPublicKey();  // use the new public key as the seed
    var symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

    // encrypt the message using the symmetric key
    var iv = crypto.randomBytes(12);
    var cipher = crypto.createCipheriv(CIPHER, symmetricKey, iv);
    var ciphertext = cipher.update(plaintext, 'utf8', 'base64');
    ciphertext += cipher.final('base64');
    var tag = cipher.getAuthTag();
    return {
        iv: iv,
        tag: tag,
        seed: seed,
        ciphertext: ciphertext
    };
}

function decryptV1(privateKey, message) {
    // decrypt the 32-byte symmetric key
    var seed = message.seed;
    var curve = crypto.createECDH(CURVE);
    curve.setPrivateKey(privateKey);
    var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

    // decrypt the message using the symmetric key
    var iv = message.iv;
    var tag = message.tag;
    var ciphertext = message.ciphertext;
    var decipher = crypto.createDecipheriv(CIPHER, symmetricKey, iv);
    decipher.setAuthTag(tag);
    var plaintext = decipher.update(ciphertext, 'base64', 'utf8');
    plaintext += decipher.final('utf8');
    return plaintext;
}

function binaryToBuffer(binary) {
    var base32 = binary.slice(1, -1);  // remove the "'"s
    binary = codex.base32Decode(base32);
    var buffer = Buffer.from(binary, 'binary');
    return buffer;
}

function bufferToBinary(buffer) {
    var base32 = codex.base32Encode(buffer.toString('binary'), '        ');
    var binary = "'" + base32 + "\n    '";
    return binary;
}

function getNextVersion(version) {
    var number = Number(version.slice(1));
    number++;
    return 'v' + number;
}