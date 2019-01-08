/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

const mocha = require('mocha');
const expect = require('chai').expect;
const bali = require('bali-component-framework');
const notary = require('../src/DigitalNotary').api('test/config/');

describe('Bali Digital Notary™', function() {

    var certificateDocument = notary.generateKeys();
    var notaryCertificate = bali.parser.parseDocument(certificateDocument.content);
    var certificateCitation = notary.getNotaryCitation();
    var source = '[$foo: "bar"]';

    describe('Test Citations', function() {

        it('should validate the certificate', function() {
            expect(certificateDocument.toString()).to.equal(notary.getNotaryCertificate().toString());
            expect(notaryCertificate.getValue('$protocol').toString()).to.equal('v1');
            var isValid = notary.documentIsValid(notaryCertificate, certificateDocument);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', function() {
            var isValid = notary.documentMatches(certificateCitation, certificateDocument);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', function() {
            var documentCitation = notary.createCitation();
            var document = notary.notarizeDocument(documentCitation, source, bali.Pattern.from('none'));
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
            var document = notary.notarizeDocument(documentCitation, source, bali.Pattern.from('none'));

            var newCertificateDocument = notary.generateKeys();
            expect(newCertificateDocument).to.exist;  // jshint ignore:line
            var newNotaryCertificate = bali.parser.parseDocument(newCertificateDocument.content);

            document = notary.notarizeDocument(documentCitation, source, bali.Pattern.from('none'));
            isValid = notary.documentIsValid(notaryCertificate, document);
            expect(isValid).to.equal(false);

            isValid = notary.documentIsValid(newNotaryCertificate, document);
            expect(isValid).to.equal(true);

            var matches = notary.documentMatches(documentCitation, document);
            expect(matches).to.equal(true);
        });

    });

});
