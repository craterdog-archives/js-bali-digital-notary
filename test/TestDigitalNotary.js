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

    var notaryKey = new notary.NotaryKey();
    var citation = notaryKey.citation;
    var certificate = notaryKey.certificate;

    describe('Test Citations', function() {

        it('should validate the citation for the certificate', function() {
            expect(citation.documentIsValid(certificate)).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a random byte array properly', function() {
            var document = language.parseDocument(notaryKey.toString());
            expect(document).to.exist;  // jshint ignore:line
            notaryKey.notarizeDocument(document);
            var isValid = certificate.documentIsValid(document);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Encryption and Decryption', function() {

        it('should encrypt and decrypt a key properly', function() {
            var message = 'This is a test...';
            var encrypted = certificate.encryptMessage(message);
            var decrypted = notaryKey.decryptMessage(encrypted);
            expect(decrypted).to.equal(message);
        });

    });

    describe('Test Exporting and Importing', function() {

        it('should export and re-import a notary key properly', function() {
            var source1 = notaryKey.toString();
            var document1 = language.parseDocument(source1);
            var copy = new notary.NotaryKey(document1);
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
