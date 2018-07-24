/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

var notary = require('../DigitalNotary');
var language = require('bali-language/BaliLanguage');
var forge = require('node-forge');
var mocha = require('mocha');
var expect = require('chai').expect;

describe('Bali Digital Notary™', function() {

    var keypair = notary.NotaryKey.generateKeyPair();
    var notaryKey = keypair.notaryKey;
    var certificate = keypair.certificate;
    var citation = notary.DocumentCitation.recreateCitation(notaryKey.citation);

    describe('Test Citations', function() {

        it('should validate the citation for the certificate', function() {
            var document = language.parseDocument(certificate.toString());
            expect(document).to.exist;  // jshint ignore:line
            var isValid = citation.documentMatches(document);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', function() {
            var document = language.parseDocument(notaryKey.toString());
            expect(document).to.exist;  // jshint ignore:line
            notaryKey.notarizeDocument(document);
            var isValid = certificate.documentIsValid(document);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Encryption and Decryption', function() {

        it('should encrypt and decrypt a message properly', function() {
            var message = 'This is a test...';
            var encrypted = certificate.encryptMessage(message);
            var decrypted = notaryKey.decryptMessage(encrypted);
            expect(decrypted).to.equal(message);
        });

    });

    describe('Test Key Regeneration', function() {

        it('should regenerate a notary key properly', function() {
            var source = 
                    '[\n' +
                    '   $foo: "bar"\n' +
                    ']';
            var document = language.parseDocument(source);
            notaryKey.notarizeDocument(document);
            var isValid = certificate.documentIsValid(document);
            expect(isValid).to.equal(true);

            var newCertificate = notaryKey.regenerateKey();
            expect(newCertificate).to.exist;  // jshint ignore:line

            document = language.parseDocument(source);
            notaryKey.notarizeDocument(document);
            isValid = certificate.documentIsValid(document);
            expect(isValid).to.equal(false);

            isValid = newCertificate.documentIsValid(document);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Exporting and Importing', function() {

        it('should export and re-import a notary key properly', function() {
            var source1 = notaryKey.toString();
            var document1 = language.parseDocument(source1);
            var copy = notary.NotaryKey.recreateNotaryKey(document1);
            var source2 = copy.toString();
            expect(source1).to.equal(source2);
        });

        it('should export and re-import a notary certificate properly', function() {
            var source1 = certificate.toString();
            var document1 = language.parseDocument(source1);
            var copy = new notary.NotaryCertificate(document1);
            var source2 = copy.toString();
            expect(source1).to.equal(source2);
        });

    });

});
