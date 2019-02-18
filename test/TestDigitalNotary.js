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
const notary = require('../').api('test/config/');

describe('Bali Digital Notary™', function() {

    var certificateDocument;
    var notaryCertificate;
    var certificateCitation;
    var component = bali.parse('[$foo: "bar"]');

    describe('Test Key Generation', function() {

        it('should generate the keys', function() {
            certificateDocument = notary.generateKeys();
            expect(certificateDocument).to.exist;  // jshint ignore:line
        });

        it('should retrieve the notary certificate', function() {
            notaryCertificate = certificateDocument.content;
            expect(notaryCertificate).to.exist;  // jshint ignore:line
        });

        it('should retrieve the certificate citation', function() {
            certificateCitation = notary.getCitation();
            expect(certificateCitation).to.exist;  // jshint ignore:line
        });

    });

    describe('Test Signing and Verification', function() {

        it('should validate the certificate', function() {
            expect(certificateDocument.toString()).to.equal(notary.getCertificate().toString());
            expect(notaryCertificate.getValue('$protocol').toString()).to.equal('v1');
            var isValid = notary.documentIsValid(certificateDocument, notaryCertificate);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', function() {
            var isValid = notary.documentMatches(certificateDocument, certificateCitation);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', function() {
            var result = notary.notarizeComponent(component, bali.NONE);
            var isValid = notary.documentIsValid(result.document, notaryCertificate);
            expect(isValid).to.equal(true);
            var matches = notary.documentMatches(result.document, result.citation);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Encryption and Decryption', function() {

        it('should encrypt and decrypt a message properly', function() {
            var message = bali.parse('"This is a test..."');
            var encrypted = notary.encryptMessage(message, notaryCertificate);
            var decrypted = notary.decryptMessage(encrypted);
            expect(decrypted.isEqualTo(message)).to.equal(true);
        });

    });

    describe('Test Key Regeneration', function() {

        it('should regenerate a notary key properly', function() {
            var result = notary.notarizeComponent(component, bali.NONE);
            var newCertificateDocument = notary.generateKeys();
            expect(newCertificateDocument).to.exist;  // jshint ignore:line
            var newNotaryCertificate = newCertificateDocument.content;

            result = notary.notarizeComponent(component, bali.NONE);
            isValid = notary.documentIsValid(result.document, notaryCertificate);
            expect(isValid).to.equal(false);

            isValid = notary.documentIsValid(result.document, newNotaryCertificate);
            expect(isValid).to.equal(true);

            var matches = notary.documentMatches(result.document, result.citation);
            expect(matches).to.equal(true);
        });

    });

});
