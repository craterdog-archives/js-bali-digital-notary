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
var forge = require('node-forge');
var language = require('bali-language/BaliLanguage');
var random = require('bali-utilities/RandomUtilities');
var codex = require('bali-utilities/EncodingUtilities');


var V1_KEY =
        '[\n' +
        '    $version: v1\n' +
        '    $tag: %tag\n' +
        '    $n: %n\n' +
        '    $e: %e\n' +
        '    $d: %d\n' +
        '    $p: %p\n' +
        '    $q: %q\n' +
        '    $dp: %dp\n' +
        '    $dq: %dq\n' +
        '    $qinv: %qinv\n' +
        ']\n';

var V1_CERTIFICATE =
        '[\n' +
        '    $version: v1\n' +
        '    $tag: %tag\n' +
        '    $n: %n\n' +
        '    $e: %e\n' +
        ']\n';


/**
 * This constructor creates a Bali document citation. It provides both a reference to
 * the Bali document as well as a SHA-512 cryptographic hash of the contents of the
 * Bali document. If anything in the contents of the document changes later on, the
 * hash value won't match.
 * 
 * @constructor
 * @param {String} reference The URI for the Bali document to be cited.
 * @param {TreeNode|String} documentOrHash The actual Bali document to be cited or a hash of
 * the document.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {DocumentCitation} The Bali document citation.
 */
function DocumentCitation(reference, documentOrHash, optionalVersion) {
    var version = optionalVersion || 'v1';  // must not change the default later on...
    switch(version) {
        case 'v1':
            this.version = version;
            this.reference = reference;
            if (documentOrHash.constructor.name !== 'string') {
                var document = documentOrHash;
                var hasher = forge.sha512.create();
                hasher.update(document.toString());
                this.hash = codex.base32Encode(hasher.digest().getBytes()).replace(/\s/g, "");
            } else {
                this.hash = documentOrHash;
            }
            break;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + version);
    }
    return this;
}
DocumentCitation.prototype.constructor = DocumentCitation;
exports.DocumentCitation = DocumentCitation;


/**
 * This method returns a string version of the full reference including the hash
 * value.
 * 
 * @returns {String} A string version of the document citation.
 */
DocumentCitation.prototype.toString = function() {
    switch(this.version) {
        case 'v1':
            var string = this.reference.toString();
            string += '?hash=' + this.hash;
            return string;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};


/**
 * This method returns whether or not the specified Bali document matches the
 * Bali document referenced by this citation.
 * 
 * @param {String} document The Bali document to be validated.
 * @returns {Boolean} Whether or not the Bali document is valid.
 */
DocumentCitation.prototype.documentIsValid = function(document) {
    switch(this.version) {
        case 'v1':
            var hasher = forge.sha512.create();
            hasher.update(document.toString());
            var hash = codex.base32Encode(hasher.digest().getBytes()).replace(/\s/g, "");
            return this.hash === hash;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};


/**
 * This constructor creates a new notary key. If an optional PEM formatted string is
 * passed into the constructor, the key definition will be used to construct the
 * notary key. Otherwise, a new notary key and associated certificate will be
 * generated. The associated notary certificate may then be retrieved from
 * 'this.certificate'.
 * 
 * @constructor
 * @param {String} document An optional Bali document containing the notary key
 * definition. If no document is passed, a new notary key will be generated.
 * @returns {NotaryKey} The notary key.
 */
function NotaryKey(document, optionalVersion) {
    var version = optionalVersion || 'v1';  // must not change the default later on...
    switch(version) {
        case 'v1':
            this.version = version;
            if (document) {
                // extract the unique tag for this notary key
                this.tag = language.getValueForKey(document, '$tag').toString().slice(1);  // strip off '#'

                // extract the notary key
                var n = new forge.jsbn.BigInteger(language.getValueForKey(document, '$n').toString());
                var e = new forge.jsbn.BigInteger(language.getValueForKey(document, '$e').toString());
                var d = new forge.jsbn.BigInteger(language.getValueForKey(document, '$d').toString());
                var p = new forge.jsbn.BigInteger(language.getValueForKey(document, '$p').toString());
                var q = new forge.jsbn.BigInteger(language.getValueForKey(document, '$q').toString());
                var dp = new forge.jsbn.BigInteger(language.getValueForKey(document, '$dp').toString());
                var dq = new forge.jsbn.BigInteger(language.getValueForKey(document, '$dq').toString());
                var qinv = new forge.jsbn.BigInteger(language.getValueForKey(document, '$qinv').toString());
                this.key = forge.pki.rsa.setPrivateKey(n, e, d, p, q, dp, dq, qinv);

            } else {
                // generate a unique tag for this notary key
                var bytes = random.generateRandomBytes(20);
                this.tag = codex.base32Encode(bytes);

                // generate a new notary key
                var keypair = forge.rsa.generateKeyPair({bits: 2048});
                this.key = keypair.privateKey;
            }

            // construct a temporary citation for the certificate
            this.citation = 'bali:/' + this.tag;  // no hash yet...

            // create the certificate
            var source = V1_CERTIFICATE.replace(/%tag/, '#' + this.tag);
            source = source.replace(/%n/, this.key.n.toString());
            source = source.replace(/%e/, this.key.e.toString());
            document = language.parseDocument(source);
            this.notarizeDocument(document, version);

            // now construct the full citation including hash
            this.citation = new exports.DocumentCitation(this.citation, document, version);

            // cache the certificate
            this.certificate = new exports.NotaryCertificate(document, version);
            return this;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + version);
    }
}
NotaryKey.prototype.constructor = NotaryKey;
exports.NotaryKey = NotaryKey;


/**
 * This method exports the notary key definition as a Bali document.
 * 
 * @returns {String} A string containing the corresponding Bali document.
 */
NotaryKey.prototype.toString = function() {
    switch(this.version) {
        case 'v1':
            var document = V1_KEY.replace(/%tag/, '#' + this.tag);
            document = document.replace(/%n/, this.key.n.toString());
            document = document.replace(/%e/, this.key.e.toString());
            document = document.replace(/%d/, this.key.d.toString());
            document = document.replace(/%p/, this.key.p.toString());
            document = document.replace(/%q/, this.key.q.toString());
            document = document.replace(/%dp/, this.key.dP.toString());
            document = document.replace(/%dq/, this.key.dQ.toString());
            document = document.replace(/%qinv/, this.key.qInv.toString());
            return document;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};


/**
 * This method generates a new notary key and associated notary certificate. It
 * uses the old notary key to notarize the new notary certificate to prove its
 * place in the certificate chain.
 * 
 * @returns {PublicKey} The new notary certificate.
 */
NotaryKey.prototype.regenerateKey = function() {
    switch(this.version) {
        case 'v1':
            var keypair = forge.rsa.generateKeyPair({bits: 2048});
            this.key = keypair.privateKey;
            this.certificate = new exports.NotaryCertificate(this.version);
            this.certificate.tag = this.tag;
            this.certificate.key = keypair.publicKey;
            return this.certificate;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};


/**
 * This method digitally notarizes a Bali document using this notary key. The resulting
 * notary seal can be validated using the <code>sealIsValid()</code> method on the
 * associated notary certificate.
 * 
 * @param {TreeNode} document The Bali document to be notarized.
 * @returns {String} The binary string containing the notary seal.
 */
NotaryKey.prototype.notarizeDocument = function(document) {
    switch(this.version) {
        case 'v1':
            // prepare the document source
            var source = document.toString();
            source += ' <' + this.citation + '>';

            // generate the notarization signature
            var hasher = forge.sha512.create();
            hasher.update(source);
            var signer = forge.pss.create({
                md: forge.sha512.create(),
                mgf: forge.mgf1.create(forge.sha512.create()),
                saltLength: 20
            });
            var bytes = this.key.sign(hasher, signer);

            // append the notary seal to the document
            var reference = '<' + this.citation + '>';
            var binary = "'" + codex.base64Encode(bytes, '    ') + "'";
            language.addSeal(document, reference, binary);
            break;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};


/**
 * This method decrypts an authenticated encrypted message generated using the notary
 * certificate associated with this notary key. The notary certificate generated and
 * encrypted a random secret key that was used to encrypt the message. The decrypted
 * message is returned.
 * 
 * @param {Object} authenticatedMessage The authenticated encrypted message.
 * @returns {String} The decrypted message.
 */
NotaryKey.prototype.decryptMessage = function(authenticatedMessage) {
    switch(this.version) {
        case 'v1':
            // decompose the authenticated encrypted message
            var iv = authenticatedMessage.iv;
            var tag = authenticatedMessage.tag;
            var encryptedSeed = authenticatedMessage.encryptedSeed;
            var encryptedMessage = authenticatedMessage.encryptedMessage;

            // decrypt the 16-byte secret key
            var kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
            var kem = forge.kem.rsa.create(kdf1);
            var key = kem.decrypt(this.key, encryptedSeed, 16);
 
            // decrypt the message using the secret key
            var message;
            var decipher = forge.cipher.createDecipher('AES-GCM', key);
            decipher.start({iv: iv, tag: tag});
            decipher.update(forge.util.createBuffer(encryptedMessage));
            var authenticated = decipher.finish();
            // authenticated is false if there was a failure (eg: authentication tag didn't match)
            if(authenticated) {
               message = decipher.output.getBytes();
            }
            return message;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};


/**
 * This constructor creates a notary certificate using the attributes passed in.
 * 
 * @constructor
 * @param {String} document An optional Bali document containing the notary certificate
 * definition.
 * @param {String} optionalVersion An optional library version string for the
 * implementation (e.g. 'v1', 'v1.3', 'v2', etc.).  The default version is 'v1'.
 * @returns {NotaryCertificate} The notary certificate.
 */
function NotaryCertificate(document, optionalVersion) {
    var version = optionalVersion || 'v1';  // must not change the default later on...
    switch(version) {
        case 'v1':
            this.version = version;
            // extract the unique tag for this notary certificate
            this.tag = language.getValueForKey(document, '$tag').toString().slice(1);  // strip off '#'

            // extract the public key for this notary certificate
            var n = new forge.jsbn.BigInteger(language.getValueForKey(document, '$n').toString());
            var e = new forge.jsbn.BigInteger(language.getValueForKey(document, '$e').toString());
            this.key = forge.pki.rsa.setPublicKey(n, e);
            break;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + version);
    }
    return this;
}
NotaryCertificate.prototype.constructor = NotaryCertificate;
exports.NotaryCertificate = NotaryCertificate;


/**
 * This method exports the notary certificate definition as a Bali document.
 * 
 * @returns {String} A string containing the corresponding Bali document.
 */
NotaryCertificate.prototype.toString = function() {
    switch(this.version) {
        case 'v1':
            var document = V1_CERTIFICATE.replace(/%tag/, '#' + this.tag);
            document = document.replace(/%n/, this.key.n.toString());
            document = document.replace(/%e/, this.key.e.toString());
            return document;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};


/**
 * This method verifies a notary seal generated using the <code>generateSeal</code>
 * method on the associated notary key. This notary certificate is used to verify the
 * notary seal against the original Bali document.
 * 
 * used to sign the string.
 * @param {String} document The original Bali document that was notarized.
 * @param {String} seal The notary seal generated for the Bali document.
 * @returns {boolean} Whether or not the notary seal is valid.
 */
NotaryCertificate.prototype.documentIsValid = function(document) {
    switch(this.version) {
        case 'v1':
            var result = language.removeSeal(document);

            var source = result.document.toString();
            source += ' ' + result.seal.children[0];
            var hasher = forge.sha512.create();
            hasher.update(source);
            var hash = hasher.digest().getBytes();

            var signature = codex.base64Decode(result.seal.children[1].toString().slice(1, -1));
            var signer = forge.pss.create({
                md: forge.sha512.create(),
                mgf: forge.mgf1.create(forge.sha512.create()),
                saltLength: 20
            });

            var isValid = this.key.verify(hash, signature, signer);
            return isValid;
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};


/**
 * This method generates a random secret key and uses it to encrypt a message.  The
 * random secret key is then encrypted by the notary certificate and an authenticated
 * encrypted message is returned. The resulting authenticated encrypted message can
 * be decrypted using the <code>decryptMessage</code> method on the corresponding
 * notary key.
 * 
 * @param {String} message The message to be encrypted.
 * @returns {Object} The authenticated encrypted message.
 */
NotaryCertificate.prototype.encryptMessage = function(message) {
    switch(this.version) {
        case 'v1':
            // generate and encrypt a 16-byte secret key
            var kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
            var kem = forge.kem.rsa.create(kdf1);
            var result = kem.encrypt(this.key, 16);
            var key = result.key;
            var encryptedSeed = result.encapsulation;
 
            // encrypt the message using the secret key
            var iv = forge.random.getBytesSync(12);
            var cipher = forge.cipher.createCipher('AES-GCM', key);
            cipher.start({iv: iv});
            cipher.update(forge.util.createBuffer(message));
            cipher.finish();
            var encryptedMessage = cipher.output.getBytes();
            var tag = cipher.mode.tag.getBytes();

            // return all components of the authenticated message
            return {
                iv: iv,
                tag: tag,
                encryptedSeed: encryptedSeed,
                encryptedMessage: encryptedMessage
            };
        default:
            throw new Error('SECURITY: The specified version is not supported: ' + this.version);
    }
};
