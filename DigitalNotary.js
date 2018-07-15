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
var language = require('bali-language/BaliLanguage');
var NodeTypes = require('bali-language/syntax/NodeTypes');
var random = require('bali-utilities/RandomUtilities');
var codex = require('bali-utilities/EncodingUtilities');


// source templates for a notary key
var V1_KEY =
        '[\n' +
        '    $tag: %tag\n' +
        '    $version: %version\n' +
        '    $protocol: %protocol\n' +
        '    $privateKey: %privateKey\n' +
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
 * @param {TreeNode|String} documentOrProtocol An optional Bali document containing
 * the notary key definition or the protocol version to be used to generate a new
 * notary key and associated certificate.
 * @returns {NotaryKey} The resulting notary key.
 */
function NotaryKey(documentOrProtocol) {
    // initialize the arguments
    var document;
    var protocol;
    if (documentOrProtocol) {
        if (documentOrProtocol.constructor.name === 'String') {
            protocol = documentOrProtocol;
        } else if (documentOrProtocol.constructor.name === 'TreeNode' && documentOrProtocol.type === NodeTypes.DOCUMENT) {
            document = documentOrProtocol;
            protocol = language.getValueForKey(document, '$protocol').toString();
        } else {
            throw new Error('NOTARY: The constructor requires either a Bali document or a protocol version: ' + documentOrProtocol);
        }
        if (!/^v([1-9][0-9]*)(\.[1-9][0-9]*)*$/g.test(protocol)) {
            throw new Error('NOTARY: The constructor was passed an invalid protocol version: ' + protocol);
        }
    } else {
        protocol = 'v1';  // NOTE: this default value CANNOT change later on!
    }

    // construct the correct protocol version of the notary key
    switch(protocol) {
        case 'v1':
            var keypair;
            var base32;
            if (document) {
                // extract the unique tag and version number for this notary key
                this.tag = language.getValueForKey(document, '$tag').toString();
                this.version = language.getValueForKey(document, '$version').toString();

                // extract the notary key
                this.protocol = protocol;
                base32 = language.getValueForKey(document, '$privateKey').toString().slice(1, -1);  // remove the "'"s
                var binary = codex.base32Decode(base32);
                this.privateKey = Buffer.from(binary, 'binary');
                keypair = recreateV1(this.privateKey);

            } else {
                // generate a unique tag and version number for this notary key
                var bytes = random.generateRandomBytes(20);
                this.tag = '#' + codex.base32Encode(bytes);
                this.version = 'v1';

                // generate a new notary key
                this.protocol = protocol;
                keypair = generateV1();
                this.privateKey = keypair.privateKey;
            }

            // construct a temporary citation with no hash for the certificate
            var reference = V1_REFERENCE.replace(/%tag/, this.tag.toString().slice(1));
            reference = reference.replace(/%version/, this.version);
            this.citation = new URL(reference);

            // create the certificate
            var source = V1_CERTIFICATE.replace(/%tag/, this.tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%protocol/, this.protocol);
            base32 = codex.base32Encode(keypair.publicKey.toString('binary'), '        ');
            source = source.replace(/%publicKey/, "'" + base32 + "\n    '");
            document = language.parseDocument(source);
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
            var base32 = codex.base32Encode(this.privateKey.toString('binary'), '        ');
            source = source.replace(/%privateKey/, "'" + base32 + "\n    '");
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
            // generate a unique tag for this notary key
            var bytes = random.generateRandomBytes(20);
            var tag = '#' + codex.base32Encode(bytes);

            // generate a new notary key
            var keypair = generateV1();

            // construct a temporary citation for the certificate
            var reference = V1_REFERENCE.replace(/%tag/, this.tag.toString().slice(1));
            reference = reference.replace(/%version/, this.version);
            var citation = new URL(reference);

            // create the certificate
            var source = V1_CERTIFICATE.replace(/%tag/, tag);
            source = source.replace(/%version/, this.version);
            source = source.replace(/%protocol/, this.protocol);
            var base32 = codex.base32Encode(keypair.publicKey.toString('binary'), '        ');
            source = source.replace(/%publicKey/, "'" + base32 + "\n    '");
            var document = language.parseDocument(source);

            // notarize it with the old key
            this.notarizeDocument(document);

            // notarize it with the new key
            this.tag = tag;
            this.privateKey = keypair.privateKey;
            this.citation = citation;
            this.notarizeDocument(document);

            // now construct the full citation including hash
            this.citation = new exports.DocumentCitation(this.citation, document, this.protocol);

            // cache the certificate
            this.certificate = new exports.NotaryCertificate(document, this.protocol);
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
 * @param {TreeNode} document The Bali document to be notarized.
 */
NotaryKey.prototype.notarizeDocument = function(document) {
    // validate the argument
    if (!document || document.constructor.name !== 'TreeNode' || document.type !== NodeTypes.DOCUMENT) {
        throw new Error('NOTARY: The constructor only requires a Bali document: ' + document);
    }
    switch(this.protocol) {
        case 'v1':
            // prepare the document source
            var citation = '<' + this.citation.toString() + '>';
            var source = document.toString();
            source += citation;  // NOTE: the citation must be included in the signed source!

            // generate the notarization signature
            var signature = "'" + signV1(this.privateKey, source) + "\n'";

            // append the notary seal to the document
            language.addSeal(document, citation, signature);
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
 * @param {TreeNode} document A Bali document containing the notary certificate definition.
 * @returns {NotaryCertificate} The notary certificate.
 */
function NotaryCertificate(document) {
    // validate the argument
    if (!document || document.constructor.name !== 'TreeNode' || document.type !== NodeTypes.DOCUMENT) {
        throw new Error('NOTARY: The constructor requires a Bali document: ' + document);
    }
    var protocol = language.getValueForKey(document, '$protocol').toString();

    switch(protocol) {
        case 'v1':
            // extract the unique tag and version for this notary certificate
            this.tag = language.getValueForKey(document, '$tag').toString();
            this.version = language.getValueForKey(document, '$version').toString();

            // extract the protocol version and public key for this notary certificate
            this.protocol = protocol;
            var base32 = language.getValueForKey(document, '$publicKey').toString().slice(1, -1);  // remove the "'"s
            var binary = codex.base32Decode(base32);
            this.publicKey = Buffer.from(binary, 'binary');
            var sealList = language.getSeals(document);
            this.seals = [];
            for (var i = 0; i < sealList.length; i++) {
                var sealNode = sealList[i];
                var seal = {};
                seal.citation = sealNode.children[0].toString();
                seal.signature = sealNode.children[1].toString();
                this.seals.push(seal);
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
            var document = language.parseDocument(source);
            for (var i = 0; i < this.seals.length; i++) {
                var seal = this.seals[i];
                language.addSeal(document, seal.citation, seal.signature);
            }
            return document.toString();
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
 * @param {TreeNode} document The Bali document that was notarized.
 * @returns {Boolean} Whether or not the notary seal on the document is valid.
 */
NotaryCertificate.prototype.documentIsValid = function(document) {
    // validate the argument
    if (!document || document.constructor.name !== 'TreeNode' || document.type !== NodeTypes.DOCUMENT) {
        throw new Error('NOTARY: The constructor requires a Bali document: ' + document);
    }
    switch(this.protocol) {
        case 'v1':
            // separate the document from its last seal components
            var signature = language.getSignature(document).toString().slice(1, -1);  // remove the "'"s
            var citation = language.getCitation(document);
            document = language.getBody(document);

            // calculate the hash of the document
            var source = document.toString();
            source += citation;  // NOTE: the citation must be included in the signed source!

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
var V1_REFERENCE = 'bali:[$tag:%23%tag,$version:%version]';
var V1_CITATION = 'bali:[$tag:%23%tag,$version:%version,$protocol:%protocol,$hash:%hash]';

/**
 * This constructor creates a Bali document citation. It provides a reference to a
 * Bali document as well as either the actual Bali document or a SHA-512 cryptographic
 * hash of the Bali document. If anything in the contents of the document changes later
 * on, the hash value won't match and the changes can be detected.
 * 
 * @constructor
 * @param {URL} reference The URL for the Bali document to be cited.
 * @param {TreeNode|String} optionalDocument The actual Bali document to be cited.
 * @param {String} optionalProtocol The version of the Bali Notary Protocol™ that should be used to
 * create the document citation (e.g. 'v1', 'v1.3', 'v2', etc.).
 * @returns {DocumentCitation} The Bali document citation.
 */
function DocumentCitation(reference, optionalDocument, optionalProtocol) {
    // validate the arguments
    var document;
    var protocol;
    if (!reference || reference.constructor.name !== 'URL') {
        throw new Error('NOTARY: The constructor requires a URL as the first argument: ' + reference);
    }
    var catalog = language.parseComponent(reference.pathname.replace(/%23/, '#'));
    if (optionalDocument) {
        document = optionalDocument;
        if (document.constructor.name !== 'TreeNode' || document.type !== NodeTypes.DOCUMENT) {
            throw new Error('NOTARY: The constructor requires a Bali document as the second argument: ' + document);
        }
        if (!optionalProtocol) {
            throw new Error('NOTARY: The constructor requires a protocol version when a document is passed into the constructor.');
        } else {
            protocol = optionalProtocol;
        }
        if (protocol.constructor.name !== 'String' || !/^v([1-9][0-9]*)(\.[1-9][0-9]*)*$/g.test(protocol)) {
            throw new Error('NOTARY: The constructor received an invalid protocol version: ' + protocol);
        }
    } else if (optionalProtocol) {
        throw new Error('NOTARY: The constructor does not expect a protocol version when no document is passed into the constructor: ' + optionalProtocol);
    } else {
        protocol = language.getValueForKey(catalog, '$protocol');
    }

    switch(protocol) {
        case 'v1':
            this.protocol = protocol;
            this.tag = language.getValueForKey(catalog, '$tag').toString();
            this.version = language.getValueForKey(catalog, '$version').toString();
            var hash = language.getValueForKey(catalog, '$hash');
            if (hash) {
                this.hash = "'" + hash.toString() + "'";
            } else {
                this.hash = "'" + digestV1(document.toString()) + "'";
            }
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
            var string = V1_CITATION.replace(/%tag/, this.tag.toString().slice(1));
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
 * @param {String} document The Bali document to be validated.
 * @returns {Boolean} Whether or not the Bali document is valid.
 */
DocumentCitation.prototype.documentMatches = function(document) {
    // validate the argument
    if (!document || document.constructor.name !== 'TreeNode' || document.type !== NodeTypes.DOCUMENT) {
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
