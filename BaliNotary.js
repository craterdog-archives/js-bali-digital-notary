/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
var crypto = require('crypto');
var ec_pem = require('ec-pem');
var bali = require('bali-language/BaliLanguage');
var codex = require('bali-utilities/EncodingUtilities');


/**
 * This class function generates a new notary key pair and returns the notary key
 * and its corresponding notary certificate in an object.
 * 
 * @param {String} protocol The Bali version string for the protocol to use to generate the
 * keypair.
 * @returns {Object} The resulting notary key and certificate.
 */
exports.generateKeys = function(protocol) {
    // validate the argument
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The function was passed an invalid protocol: ' + protocol);
    }

    // generate the correct protocol version of the notary key pair
    switch(protocol) {
        case V1.PROTOCOL:
            // generate a new notary key
            var notaryKey = V1.generate();
            var tag = notaryKey.tag;
            var version = notaryKey.version;
            var publicKey = notaryKey.publicKey;

            // create the certificate document
            var source = V1.CERTIFICATE;
            source = source.replace(/%protocol/, protocol);
            source = source.replace(/%tag/, tag);
            source = source.replace(/%version/, version);
            source = source.replace(/%publicKey/, bufferToBinary(publicKey));
            var certificate = bali.parseDocument(source);

            // notarize the certificate document
            notaryKey.citation = exports.notarizeDocument(notaryKey, tag, version, certificate);

            return {
                notaryKey: notaryKey,
                certificate: certificate
            };
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function regenerates a notary key and associated notary certificate. It
 * uses the old notary key to notarize the new notary certificate to prove its
 * place in the notary certificate chain.
 * 
 * @param {NotaryKey} notaryKey The existing notary key to be regenerated.
 * @returns {NotaryCertificate} The new notary certificate.
 */
exports.regenerateKeys = function(notaryKey) {
    // validate the argument
    if (!isNotaryKey(notaryKey)) {
        throw new Error('NOTARY: The function was passed an invalid notary key: ' + notaryKey);
    }

    // generate the correct protocol version of the notary key pair
    var protocol = notaryKey.protocol;
    switch(protocol) {
        case V1.PROTOCOL:
            // generate a new notary key
            var newKey = V1.generate(notaryKey);
            var tag = newKey.tag;
            var version = newKey.version;
            var publicKey = newKey.publicKey;

            // create the certificate document
            var source = V1.CERTIFICATE;
            source = source.replace(/%protocol/, protocol);
            source = source.replace(/%tag/, tag);
            source = source.replace(/%version/, version);
            source = source.replace(/%publicKey/, bufferToBinary(publicKey));
            var certificate = bali.parseDocument(source);

            // notarize the new certificate with the old key and new key
            exports.notarizeDocument(notaryKey, tag, version, certificate);
            newKey.citation = exports.notarizeDocument(newKey, tag, version, certificate);

            return {
                notaryKey: newKey,
                certificate: certificate
            };
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function digitally notarizes a Bali document using this notary key. The resulting
 * notary seal is appended to the document and can be validated using the
 * <code>documentIsValid()</code> method on the associated notary certificate.
 * 
 * @param {NotaryKey} notaryKey The notary key to be used to notarize the document.
 * @param {String} tag The unique tag for the document to be notarized.
 * @param {String} version The version number of the document to be notarized.
 * @param {Document} document The document to be notarized.
 * @returns {DocumentCitation} A citation to the resulting notarized document.
 */
exports.notarizeDocument = function(notaryKey, tag, version, document) {
    // validate the arguments
    if (!isNotaryKey(notaryKey)) {
        throw new Error('NOTARY: The function was passed an invalid notary key: ' + notaryKey);
    }
    if (!bali.isTag(tag)) {
        throw new Error('NOTARY: The function was passed an invalid Bali tag: ' + tag);
    }
    if (!bali.isVersion(version)) {
        throw new Error('NOTARY: The function was passed an invalid Bali version: ' + version);
    }
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
    }
    var protocol = notaryKey.protocol;
    var certificateCitation = notaryKey.citation;
    switch(protocol) {
        case V1.PROTOCOL:
            // prepare the document source
            var source = document.toString();
            source += certificateCitation;  // NOTE: the citation must be included in the signed source!

            // generate the notarization signature
            var signature = "'" + V1.sign(notaryKey, source) + "\n'";

            // append the notary seal to the document
            bali.addSeal(document, certificateCitation, signature);

            // generate a citation to the notarized document
            var documentCitation = V1.CITATION;
            documentCitation = documentCitation.replace(/%protocol/, protocol);
            documentCitation = documentCitation.replace(/%tag/, tag);
            documentCitation = documentCitation.replace(/%version/, version);
            documentCitation = documentCitation.replace(/%hash/, "'" + V1.digest(document.toString()) + "'");
            break;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
    return documentCitation;
};


/**
 * This function decrypts an authenticated encrypted message generated using the notary
 * certificate associated with this notary key. The notary certificate generated and
 * encrypted a random secret key that was used to encrypt the original message. The
 * decrypted message is returned from this method.
 * 
 * @param {NotaryKey} notaryKey The notary key to be used to decrypt the message.
 * @param {Object} aem The authenticated encrypted message.
 * @returns {String} The decrypted message.
 */
exports.decryptMessage = function(notaryKey, aem) {
    // validate the arguments
    if (!isNotaryKey(notaryKey)) {
        throw new Error('NOTARY: The function was passed an invalid notary key: ' + notaryKey);
    }
    var protocol = notaryKey.protocol;
    switch(protocol) {
        case V1.PROTOCOL:
            var message = V1.decrypt(notaryKey, aem);
            return message;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function validates a Bali document that was notarized using the
 * <code>notarizeDocument</code> method on the associated notary key. This notary
 * certificate is used to verify the notary seal that is appended to the Bali
 * document.
 * 
 * @param {Document} certificate The Bali certificate to be used to validate the document.
 * @param {Document} document The Bali document that was notarized.
 * @returns {Boolean} Whether or not the notary seal on the document is valid.
 */
exports.documentIsValid = function(certificate, document) {
    // validate the arguments
    if (!bali.isDocument(certificate)) {
        throw new Error('NOTARY: The function was passed an invalid Bali certificate: ' + certificate);
    }
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
    }
    var protocol = bali.getStringForKey(certificate, '$protocol');
    var publicKey = binaryToBuffer(bali.getStringForKey(certificate, '$publicKey'));
    switch(protocol) {
        case V1.PROTOCOL:
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
            var isValid = V1.verify(publicKey, source, signature);
            return isValid;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function generates a random symmetric key and uses it to encrypt a message.  The
 * symmetric key is then encrypted by the notary certificate and an authenticated
 * encrypted message is returned. The resulting authenticated encrypted message can
 * be decrypted using the <code>decryptMessage</code> method on the corresponding
 * notary key.
 * 
 * @param {Document} certificate The Bali certificate to be used to encrypt the message.
 * @param {String} message The message to be encrypted.
 * @returns {Object} The resulting authenticated encrypted message.
 */
exports.encryptMessage = function(certificate, message) {
    // validate the arguments
    if (!bali.isDocument(certificate)) {
        throw new Error('NOTARY: The function was passed an invalid Bali certificate: ' + certificate);
    }
    var protocol = bali.getStringForKey(certificate, '$protocol');
    var publicKey = binaryToBuffer(bali.getStringForKey(certificate, '$publicKey'));
    switch(protocol) {
        case V1.PROTOCOL:
            var aem = V1.encrypt(publicKey, message);
            return aem;
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


/**
 * This function determines whether or not the specified document matches EXACTLY the
 * document referenced by this citation.
 * 
 * @param {String} citation A citation to the document to be checked.
 * @param {String} document The document to be checked.
 * @returns {Boolean} Whether or not the document hash value matches.
 */
exports.documentMatches = function(citation, document) {
    // validate the arguments
    if (!isCitation(citation)) {
        throw new Error('NOTARY: The function was passed an invalid document citation: ' + citation);
    }
    if (!bali.isDocument(document)) {
        throw new Error('NOTARY: The function was passed an invalid Bali document: ' + document);
    }
    var catalog = bali.parseComponent(citation.slice(6, -1));
    var protocol = bali.getStringForKey(catalog, '$protocol');
    var hash = bali.getStringForKey(catalog, '$hash');
    if (!bali.isVersion(protocol)) {
        throw new Error('NOTARY: The constructor received a reference with an invalid protocol version: ' + protocol);
    }
    switch(protocol) {
        case V1.PROTOCOL:
            return hash === "'" + V1.digest(document.toString()) + "'";
        default:
            throw new Error('NOTARY: The specified protocol version is not supported: ' + protocol);
    }
};


// PRIVATE FUNCTIONS

function isNotaryKey(notaryKey) {
    return notaryKey ? true : false;
}

function isCitation(citation) {
    return citation ? true : false;
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


// PROTOCOL CLASSES

var V1 = {

    PROTOCOL: 'v1',
    CURVE: 'secp521r1',
    DIGEST: 'sha512',
    SIGNATURE: 'ecdsa-with-SHA1',
    CIPHER: 'aes-256-gcm',

    KEY:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $publicKey: %publicKey\n' +
        '    $citation: %citation\n' +
        ']\n',

    CERTIFICATE:
        '[\n' +
        '    $protocol: %protocol\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $publicKey: %publicKey\n' +
        ']\n',

    REFERENCE: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version]>',

    CITATION: '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$hash:%hash]>',

    keys: new Map(),

    digest: function(message) {
        var hasher = crypto.createHash(V1.DIGEST);
        hasher.update(message);
        var binary = hasher.digest().toString('binary');
        var digest = codex.base32Encode(binary).replace(/\s+/g, '');  // strip out any whitespace
        return digest;
    },

    generate: function(notaryKey) {
        var tag;
        var version;
        if (notaryKey) {
            // regenerate existing notary key
            tag = notaryKey.tag;
            version = 'v' + (Number(notaryKey.version.slice(1)) + 1);
        } else {
            // generate a new notary key
            tag = bali.tag().toString();
            version = 'v1';
        }
        var curve = crypto.createECDH(V1.CURVE);
        curve.generateKeys();
        var publicKey = curve.getPublicKey();
        notaryKey = new V1.NotaryKey(tag, version, publicKey);
        var keyId = tag + version;
        V1.keys.set(keyId, curve.getPrivateKey());
        return notaryKey;
    },

    recreate: function(tag, version, publicKey) {
        var notaryKey = new V1.NotaryKey(tag, version, publicKey);
        return notaryKey;
    },

    forget: function(notaryKey) {
        var keyId = notaryKey.tag + notaryKey.version;
        V1.keys.delete(keyId);
    },

    sign: function(notaryKey, message) {
        var keyId = notaryKey.tag + notaryKey.version;
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(V1.keys.get(keyId));
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
        var ciphertext = cipher.update(plaintext, 'utf8', 'base64');
        ciphertext += cipher.final('base64');
        var tag = cipher.getAuthTag();
        var aem = {
            version: V1.PROTOCOL,
            iv: iv,
            tag: tag,
            seed: seed,
            ciphertext: ciphertext
        };
        return aem;
    },

    decrypt: function(notaryKey, aem) {
        var keyId = notaryKey.tag + notaryKey.version;
        // decrypt the 32-byte symmetric key
        var seed = aem.seed;
        var curve = crypto.createECDH(V1.CURVE);
        curve.setPrivateKey(V1.keys.get(keyId));
        var symmetricKey = curve.computeSecret(seed).slice(0, 32);  // take only first 32 bytes

        // decrypt the ciphertext using the symmetric key
        var decipher = crypto.createDecipheriv(V1.CIPHER, symmetricKey, aem.iv);
        decipher.setAuthTag(aem.tag);
        var plaintext = decipher.update(aem.ciphertext, 'base64', 'utf8');
        plaintext += decipher.final('utf8');
        return plaintext;
    },

    NotaryKey: function(tag, version, publicKey) {
        this.protocol = V1.PROTOCOL;
        this.tag = tag;
        this.version = version;
        this.publicKey = publicKey;
        var citation = V1.REFERENCE;
        citation = citation.replace(/%protocol/, V1.PROTOCOL);
        citation = citation.replace(/%tag/, tag);
        citation = citation.replace(/%version/, version);
        this.citation = citation;

        this.toString = function() {
            var source = V1.KEY;
            source = source.replace(/%protocol/, this.protocol);
            source = source.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%publicKey/, bufferToBinary(this.publicKey));
            source = source.replace(/%citation/, this.citation);
            return source;
        };

        return this;
    }
};
