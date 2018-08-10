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


/**
 * This class function generates a new notary key pair and returns the notary key
 * and its corresponding notary certificate in an object.
 * 
 * @param {Version} protocol The Bali version string for the protocol to use to generate the
 * keypair.
 * @returns {Object} The resulting notary key and certificate.
 */
NotaryKey.generateKeyPair = function(protocol) {
    // validate the argument
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The constructor was passed an invalid protocol: ' + protocol);
    }

    // generate the correct protocol version of the notary key pair
    var notaryKey = new NotaryKey();
    switch(protocol) {
        case 'v1':
            // generate a unique tag and version number for this notary key
            notaryKey.tag = bali.tag();
            notaryKey.version = 'v1';  // the initial version of the notary key

            // generate a new notary key
            notaryKey.protocol = protocol;
            var keypair = V1.generate();
            notaryKey.publicKey = keypair.publicKey;
            notaryKey.privateKey = keypair.privateKey;

            // construct a temporary citation with no hash for the certificate
            var reference = V1.REFERENCE.replace(/%tag/, notaryKey.tag);
            reference = reference.replace(/%version/, notaryKey.version);
            reference = reference.replace(/%protocol/, notaryKey.protocol);
            notaryKey.citation = DocumentCitation.generateCitation(reference, null, protocol);

            // create the certificate document
            var source = V1.CERTIFICATE.replace(/%tag/, notaryKey.tag);
            source = source.replace(/%version/, notaryKey.version);
            source = source.replace(/%protocol/, notaryKey.protocol);
            source = source.replace(/%publicKey/, bufferToBinary(notaryKey.publicKey));
            var document = bali.parseDocument(source);
            notaryKey.notarizeDocument(document);

            // now construct the full citation including the hash
            notaryKey.citation = DocumentCitation.generateCitation(reference, document, protocol);

            // generate the notarized certificate
            var certificate = NotaryCertificate.recreateCertificate(document);

            return {
                notaryKey: notaryKey,
                certificate: certificate
            };
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This class function recreates a notary key from a Bali document.
 * 
 * @param {Document} document The Bali document containing the notary key definition.
 * @returns {NotaryKey} The recreated notary key.
 */
NotaryKey.recreateNotaryKey = function(document) {
    // validate the argument
    var protocol;
    if (bali.isDocument(document)) {
        protocol = bali.getStringForKey(document, '$protocol');
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
            notaryKey.tag = bali.getStringForKey(document, '$tag');
            notaryKey.version = bali.getStringForKey(document, '$version');

            // extract the key pair
            notaryKey.protocol = protocol;
            var binary = bali.getStringForKey(document, '$privateKey');
            notaryKey.privateKey = binaryToBuffer(binary);
            binary = bali.getStringForKey(document, '$publicKey');
            notaryKey.publicKey = binaryToBuffer(binary);
            var reference = bali.getStringForKey(document, '$citation');
            notaryKey.citation = DocumentCitation.recreateCitation(reference);

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
            var source = V1.KEY.replace(/%tag/, this.tag);
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
            var keypair = V1.generate();

            // construct a temporary citation for the certificate
            var reference = V1.REFERENCE.replace(/%tag/, this.tag);
            reference = reference.replace(/%version/, nextVersion);
            reference = reference.replace(/%protocol/, this.protocol);

            // create the certificate
            var source = V1.CERTIFICATE.replace(/%tag/, this.tag);
            source = source.replace(/%version/, nextVersion);
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%publicKey/, bufferToBinary(keypair.publicKey));
            source = this.citation.toString() + '\n' + source;  // now it's a citation to the previous certificate
            var document = bali.parseDocument(source);

            // notarize it with the old key
            this.notarizeDocument(document);

            // notarize it with the new key
            this.version = nextVersion;
            this.publicKey = keypair.publicKey;
            this.privateKey = keypair.privateKey;
            this.previous = this.citation;
            this.citation = DocumentCitation.generateCitation(reference, null, this.protocol);
            this.notarizeDocument(document);

            // now construct the full citation including hash
            this.citation = DocumentCitation.generateCitation(reference, document, this.protocol);

            var certificate = NotaryCertificate.recreateCertificate(document);
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
            var signature = "'" + V1.sign(this.privateKey, source) + "\n'";

            // append the notary seal to the document
            bali.addSeal(document, this.citation.toString(), signature);
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
            var plaintext = V1.decrypt(this.privateKey, message);
            return plaintext;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


function NotaryCertificate() {
    return this;
}
NotaryCertificate.prototype.constructor = NotaryCertificate;
exports.NotaryCertificate = NotaryCertificate;


/**
 * This class function recreates a notary certificate from a Bali document.
 * 
 * @param {Document} document The Bali document containing the notary certificate definition.
 * @returns {NotaryCertificate} The recreated notary certificate.
 */
NotaryCertificate.recreateCertificate = function(document) {
    // validate the argument
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The constructor received an invalid document: ' + document);
    }
    var protocol = bali.getStringForKey(document, '$protocol');
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The constructor received an invalid protocol version: ' + protocol);
    }

    // recreate the notary certificate
    var certificate = new NotaryCertificate();
    switch(protocol) {
        case 'v1':
            // extract the unique tag and version for this notary certificate
            certificate.tag = bali.getStringForKey(document, '$tag');
            certificate.version = bali.getStringForKey(document, '$version');
            certificate.protocol = protocol;

            // extract the public key for this notary certificate
            var binary = bali.getStringForKey(document, '$publicKey');
            certificate.publicKey = binaryToBuffer(binary);

            // extract the notary seals for this notary certificate
            var sealList = bali.getSeals(document);
            certificate.seals = [];
            var reference;
            for (var i = 0; i < sealList.length; i++) {
                var sealNode = sealList[i];
                var seal = {};
                seal.citation = bali.getCitation(sealNode).toString();
                seal.signature = bali.getSignature(sealNode).toString();
                certificate.seals.push(seal);
            }
            if (certificate.version !== 'v1') {
                reference = bali.getPreviousCitation(document).toString();
                certificate.previous = DocumentCitation.recreateCitation(reference);
            }
            return certificate;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This method exports the notary certificate definition as Bali document source.
 * 
 * @returns {String} A string containing the corresponding Bali document source.
 */
NotaryCertificate.prototype.toString = function() {
    switch(this.protocol) {
        case 'v1':
            var source = V1.CERTIFICATE.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%protocol/, this.protocol);
            var base32 = codex.base32Encode(this.publicKey.toString('binary'), '        ');
            source = source.replace(/%publicKey/, "'" + base32 + "\n    '");
            for (var i = 0; i < this.seals.length; i++) {
                var seal = this.seals[i];
                source += seal.citation + ' ' + seal.signature + '\n';
            }
            if (this.previous) {
                source = this.previous.toString() + '\n' + source;
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
            var isValid = V1.verify(this.publicKey, source, signature);
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
            var ciphertext = V1.encrypt(this.publicKey, message);
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


/**
 * This class function generates a new document citation for a specific document. If
 * no document is specified, the citation is for a self-notarized document like a
 * notary certificate.
 * 
 * @param {Reference} reference A Bali reference to the document to be cited.
 * @param {String} document The document to be cited.
 * @param {Version} protocol The Bali version string for the protocol version to be
 * used to generate the document citation.
 * @returns {DocumentCitation} The resulting document citation.
 */
DocumentCitation.generateCitation = function(reference, document, protocol) {
    // validate the arguments
    if (!bali.isReference(reference)) {
        throw new Error('NOTARY: The constructor received an invalid reference: ' + reference);
    }
    var url = new URL(reference.slice(1, -1).replace(/#/, '%23'));
    var catalog = bali.parseComponent(url.pathname.replace(/%23/, '#'));
    if (document && !bali.isDocument(document)) {
        throw new Error('NOTARY: The constructor received an invalid document: ' + document);
    }
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The constructor received an invalid protocol version: ' + protocol);
    }

    // generate the citation
    var citation = new DocumentCitation();
    switch(protocol) {
        case 'v1':
            citation.tag = bali.getStringForKey(catalog, '$tag');
            citation.version = bali.getStringForKey(catalog, '$version');
            citation.protocol = protocol;
            if (document) {
                citation.hash = "'" + V1.digest(document.toString()) + "'";
            }
            return citation;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This class function recreates a document citation from a Bali reference.
 * 
 * @param {Reference} reference The Bali reference containing the document citation definition.
 * @returns {DocumentCitation} The recreated document citation.
 */
DocumentCitation.recreateCitation = function(reference) {
    // validate the arguments
    var protocol;
    if (!bali.isReference(reference)) {
        throw new Error('NOTARY: The constructor received an invalid reference: ' + reference);
    }
    var url = new URL(reference.slice(1, -1).replace(/#/, '%23'));
    var catalog = bali.parseComponent(url.pathname.replace(/%23/, '#'));
    protocol = bali.getStringForKey(catalog, '$protocol');
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The constructor received a reference with an invalid protocol version: ' + protocol);
    }

    // recreate the citation
    var citation = new DocumentCitation();
    switch(protocol) {
        case 'v1':
            citation.tag = bali.getStringForKey(catalog, '$tag');
            citation.version = bali.getStringForKey(catalog, '$version');
            citation.protocol = protocol;
            citation.hash = bali.getStringForKey(catalog, '$hash');
            return citation;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This method exports the document citation as a Bali source text string.
 * value.
 * 
 * @returns {String} A string version of the document citation.
 */
DocumentCitation.prototype.toString = function() {
    switch(this.protocol) {
        case 'v1':
            var string = this.hash ? V1.CITATION : V1.REFERENCE;
            string = string.replace(/%tag/, this.tag);
            string = string.replace(/%version/, this.version);
            string = string.replace(/%protocol/, this.protocol);
            if (this.hash) string = string.replace(/%hash/, this.hash);
            return string;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


/**
 * This method determines whether or not the specified document matches EXACTLY the
 * document referenced by this citation.
 * 
 * @param {String} document The document to be checked.
 * @returns {Boolean} Whether or not the document hash value matches.
 */
DocumentCitation.prototype.documentMatches = function(document) {
    // validate the argument
    if (!document || !bali.isDocument(document)) {
        throw new Error('NOTARY: An invalid document was passed as the argument: ' + document);
    }
    switch(this.protocol) {
        case 'v1':
            var hash = V1.digest(document.toString());
            return this.hash === "'" + hash + "'";
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + this.protocol);
    }
};


// PRIVATE FUNCTIONS

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


// PROTOCOL CLASSES

var V1 = {

    CURVE: 'secp521r1',
    DIGEST: 'sha512',
    SIGNATURE: 'ecdsa-with-SHA1',
    CIPHER: 'aes-256-gcm',

    KEY:
        '[\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $protocol: %protocol\n' +
        '    $privateKey: %privateKey\n' +
        '    $publicKey: %publicKey\n' +
        '    $citation: %citation\n' +
        ']\n',

    CERTIFICATE:
        '[\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $protocol: %protocol\n' +
        '    $publicKey: %publicKey\n' +
        ']\n',

    REFERENCE: '<bali:[$tag:%tag,$version:%version,$protocol:%protocol]>',

    CITATION: '<bali:[$tag:%tag,$version:%version,$protocol:%protocol,$hash:%hash]>',

    digest: function(message) {
        var hasher = crypto.createHash(V1.DIGEST);
        hasher.update(message);
        var binary = hasher.digest().toString('binary');
        var digest = codex.base32Encode(binary).replace(/\s+/g, '');  // strip out any whitespace
        return digest;
    },

    generate: function() {
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        return {
            privateKey: curve.getPrivateKey(),
            publicKey: curve.getPublicKey()
        };
    },

    sign: function(privateKey, message) {
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(privateKey);
        var pem = ec_pem(curve, V1.CURVE);
        var signer = crypto.createSign(V1.SIGNATURE);
        signer.update(message);
        var binary = signer.sign(pem.encodePrivateKey(), 'binary');
        var signature = codex.base32Encode(binary, '    ');
        return signature;
    },

    verify: function(publicKey, message, signature) {
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPublicKey(publicKey);
        var pem = ec_pem(curve, V1.CURVE);
        var verifier = crypto.createVerify(V1.SIGNATURE);
        verifier.update(message);
        var binary = codex.base32Decode(signature);
        return verifier.verify(pem.encodePublicKey(), binary, 'binary');
    },

    encrypt: function(publicKey, plaintext) {
        // generate and encrypt a 32-byte symmetric key
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        var seed = curve.getPublicKey();  // use the new public key as the seed
        var symmetricKey = curve.computeSecret(publicKey).slice(0, 32);  // take only first 32 bytes

        // encrypt the message using the symmetric key
        var iv = crypto.randomBytes(12);
        var cipher = crypto.createCipheriv(V1.CIPHER, symmetricKey, iv);
        var bytes = cipher.update(plaintext, 'utf8', 'base64');
        bytes += cipher.final('base64');
        var tag = cipher.getAuthTag();
        var ciphertext = {
            iv: iv,
            tag: tag,
            seed: seed,
            bytes: bytes,
            version: 'v1'
        };
        return ciphertext;
    },

    decrypt: function(privateKey, ciphertext) {
        // decrypt the 32-byte symmetric key
        var seed = ciphertext.seed;
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(privateKey);
        var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

        // decrypt the ciphertext using the symmetric key
        var iv = ciphertext.iv;
        var tag = ciphertext.tag;
        var bytes = ciphertext.bytes;
        var decipher = crypto.createDecipheriv(V1.CIPHER, symmetricKey, iv);
        decipher.setAuthTag(tag);
        var plaintext = decipher.update(bytes, 'base64', 'utf8');
        plaintext += decipher.final('utf8');
        return plaintext;
    }
};
