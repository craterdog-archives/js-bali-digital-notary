/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

var mocha = require('mocha');
var expect = require('chai').expect;
var bali = require('bali-component-framework');
var notary = require('../src/DigitalNotary').api('test/config/');
var NotarizedDocument = require('../src/NotarizedDocument').NotarizedDocument;

describe('Bali Digital Notary™', function() {

    var notaryCertificate = notary.generateKeys();
    var certificateCitation = notary.getNotaryCitation();
    var source = '[$foo: "bar"]\n-----\nnone\n';  // add POSIX compliant end of line

    describe('Test Citations', function() {

        it('should validate the certificate', function() {
            expect(notaryCertificate.documentContent.isEqualTo(notary.getNotaryCertificate().documentContent)).to.equal(true);
            var protocol = notaryCertificate.getValue('$protocol');
            expect(protocol.toString()).to.equal('v1');
            var isValid = notary.documentIsValid(notaryCertificate, notaryCertificate);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', function() {
            var isValid = notary.documentMatches(certificateCitation, notaryCertificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', function() {
            var documentCitation = notary.createCitation();
            var document = NotarizedDocument.fromString(source);
            documentCitation = notary.notarizeDocument(documentCitation, document);
            var isValid = notary.documentIsValid(notaryCertificate, document);
            expect(isValid).to.equal(true);
            var matches = notary.documentMatches(documentCitation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Encryption and Decryption', function() {

        it('should encrypt and decrypt a message properly', function() {
            var message = 'This is a test...';
            var encrypted = notary.encryptMessage(notaryCertificate, message);
            var decrypted = notary.decryptMessage(encrypted);
            expect(decrypted).to.equal(message);
        });

    });

    describe('Test Key Regeneration', function() {

        it('should regenerate a notary key properly', function() {
            var documentCitation = notary.createCitation();
            var document = NotarizedDocument.fromString(source);
            documentCitation = notary.notarizeDocument(documentCitation, document);

            var newCertificate = notary.generateKeys();
            expect(notaryCertificate).to.exist;  // jshint ignore:line

            document = NotarizedDocument.fromString(source);
            var newDocumentCitation = notary.notarizeDocument(documentCitation, document);
            isValid = notary.documentIsValid(notaryCertificate, document);
            expect(isValid).to.equal(false);

            isValid = notary.documentIsValid(newCertificate, document);
            expect(isValid).to.equal(true);

            var matches = notary.documentMatches(newDocumentCitation, document);
            expect(matches).to.equal(true);
        });

    });

});
