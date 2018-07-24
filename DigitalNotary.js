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


function NotaryKey() {
    return this;
}
NotaryKey.prototype.constructor = NotaryKey;
exports.NotaryKey = NotaryKey;


// source templates for a notary key
var V1_KEY =
        '[\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $protocol: %protocol\n' +
        '    $privateKey: %privateKey\n' +
        '    $publicKey: %publicKey\n' +
        '    $citation: %citation\n' +
        ']';

NotaryKey.generateKeyPair = function(optionalProtocol) {
    // validate the argument
    var protocol;
    if (optionalProtocol) {
        if (bali.isVersion(optionalProtocol)) {
            protocol = optionalProtocol;
        } else {
            throw new Error('NOTARY: The constructor was passed an invalid protocol: ' + optionalProtocol);
        }
    } else {
        protocol = 'v1';  // NOTE: this default value CANNOT change later on!
    }

    // generate the correct protocol version of the notary key
    var notaryKey = new NotaryKey();
    switch(protocol) {
        case 'v1':
            // generate a unique tag and version number for this notary key
            notaryKey.tag = bali.tag();
            notaryKey.version = 'v1';  // the initial version of the notary key

            // generate a new notary key
            notaryKey.protocol = protocol;
            var keypair = generateV1();
            notaryKey.publicKey = keypair.publicKey;
            notaryKey.privateKey = keypair.privateKey;

            // construct a temporary citation with no hash for the certificate
            var reference = V1_REFERENCE.replace(/%tag/, notaryKey.tag);
            notaryKey.citation = reference.replace(/%version/, notaryKey.version);

            // create the certificate document
            var source = V1_CERTIFICATE.replace(/%tag/, notaryKey.tag);
            source = source.replace(/%version/, notaryKey.version);
            source = source.replace(/%protocol/, notaryKey.protocol);
            source = source.replace(/%publicKey/, bufferToBinary(notaryKey.publicKey));
            var document = bali.parseDocument(source);
            notaryKey.notarizeDocument(document);

            // now construct the full citation including the hash
            notaryKey.citation = DocumentCitation.generateCitation(notaryKey.citation, document, protocol).toString();

            // generate the notarized certificate
            var certificate = new exports.NotaryCertificate(document);

            return {
                notaryKey: notaryKey,
                certificate: certificate
            };
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


NotaryKey.recreateNotaryKey = function(document) {
    // validate the argument
    var protocol;
    if (bali.isDocument(document)) {
        protocol = bali.getValueForKey(document, '$protocol').toString();
        if (!bali.isVersion(protocol)) {
            throw new Error('NOTARY: The constructor was passed a document with an invalid protocol version: ' + protocol);
        }
    } else {
        throw new Error('NOTARY: The constructor was passed an invalid document: ' + document);
    }

    // construct the correct protocol version of the notary key
    var notaryKey = new NotaryKey();
    switch(protocol) {
        case 'v1':
            // extract the unique tag and version number for this notary key
            notaryKey.tag = bali.getValueForKey(document, '$tag').toString();
            notaryKey.version = bali.getValueForKey(document, '$version').toString();

            // extract the key pair
            notaryKey.protocol = protocol;
            var binary = bali.getValueForKey(document, '$privateKey').toString();
            notaryKey.privateKey = binaryToBuffer(binary);
            binary = bali.getValueForKey(document, '$publicKey').toString();
            notaryKey.publicKey = binaryToBuffer(binary);
            notaryKey.citation = bali.getValueForKey(document, '$citation').toString();

            return notaryKey;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


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
            source = source.replace(/%privateKey/, bufferToBinary(this.privateKey));
            source = source.replace(/%publicKey/, bufferToBinary(this.publicKey));
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
            this.citation = DocumentCitation.generateCitation(citation, document, this.protocol).toString();

            var certificate = new exports.NotaryCertificate(document);
            return certificate;
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


// source templates for a notary certificate
var V1_CERTIFICATE =
        '[\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $protocol: %protocol\n' +
        '    $publicKey: %publicKey\n' +
        ']';

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


function DocumentCitation() {
    return this;
}
DocumentCitation.prototype.constructor = DocumentCitation;
exports.DocumentCitation = DocumentCitation;


// source templates for a document reference and citation
var V1_REFERENCE = '<bali:[$tag:%tag,$version:%version]>';
var V1_CITATION = '<bali:[$tag:%tag,$version:%version,$protocol:%protocol,$hash:%hash]>';

DocumentCitation.generateCitation = function(reference, document, optionalProtocol) {
    // validate the arguments
    var protocol;
    if (!bali.isReference(reference)) {
        throw new Error('NOTARY: The constructor received an invalid reference: ' + reference);
    }
    var url = new URL(reference.slice(1, -1).replace(/#/, '%23'));
    var catalog = bali.parseComponent(url.pathname.replace(/%23/, '#'));
    if (bali.isDocument(document)) {
        if (optionalProtocol) {
            if (bali.isVersion(optionalProtocol)) {
                protocol = optionalProtocol;
            } else {
                throw new Error('NOTARY: The constructor received an invalid protocol version: ' + optionalProtocol);
            }
        } else {
            protocol = 'v1';  // NOTE: this default value CANNOT change later on!
        }
    } else {
        throw new Error('NOTARY: The constructor received an invalid document: ' + document);
    }

    var citation = new DocumentCitation();
    switch(protocol) {
        case 'v1':
            citation.tag = bali.getValueForKey(catalog, '$tag').toString();
            citation.version = bali.getValueForKey(catalog, '$version').toString();
            citation.protocol = protocol;
            citation.hash = "'" + digestV1(document.toString()) + "'";
            return citation;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


DocumentCitation.recreateCitation = function(reference) {
    // validate the arguments
    var protocol;
    if (!bali.isReference(reference)) {
        throw new Error('NOTARY: The constructor received an invalid referencet: ' + reference);
    }
    var url = new URL(reference.slice(1, -1).replace(/#/, '%23'));
    var catalog = bali.parseComponent(url.pathname.replace(/%23/, '#'));
    protocol = bali.getValueForKey(catalog, '$protocol').toString();
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The constructor received a reference with an invalid protocol version: ' + protocol);
    }

    var citation = new DocumentCitation();
    switch(protocol) {
        case 'v1':
            citation.tag = bali.getValueForKey(catalog, '$tag').toString();
            citation.version = bali.getValueForKey(catalog, '$version').toString();
            citation.protocol = protocol;
            citation.hash = bali.getValueForKey(catalog, '$hash').toString();
            return citation;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


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