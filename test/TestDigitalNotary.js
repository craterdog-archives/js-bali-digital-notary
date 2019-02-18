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

        it('should support correct versions', function() {
            const versions = notary.supportedVersions();
            expect(versions.toString()).to.equal('[v1]');
        });

        it('should generate the keys', function() {
            certificateDocument = notary.generateKeys();
            expect(certificateDocument).to.exist;  // jshint ignore:line
        });

        it('should retrieve the notary certificate', function() {
            notaryCertificate = certificateDocument.getValue('$content');
            expect(notaryCertificate).to.exist;  // jshint ignore:line
        });

        it('should retrieve the certificate citation', function() {
            certificateCitation = notary.getCitation();
            expect(certificateCitation).to.exist;  // jshint ignore:line
        });

    });

    describe('Test Certificate Validation', function() {

        it('should validate the certificate', function() {
            expect(certificateDocument.toString()).to.equal(notary.getCertificate().toString());
            expect(notaryCertificate.getParameters().getParameter('$protocol').toString()).to.equal('v1');
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
            var result = notary.notarizeComponent(component);
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
            var result = notary.notarizeComponent(component);
            var newCertificateDocument = notary.generateKeys();
            expect(newCertificateDocument).to.exist;  // jshint ignore:line
            var newNotaryCertificate = newCertificateDocument.getValue('$content');

            result = notary.notarizeComponent(component);
            isValid = notary.documentIsValid(result.document, notaryCertificate);
            expect(isValid).to.equal(false);

            isValid = notary.documentIsValid(result.document, newNotaryCertificate);
            expect(isValid).to.equal(true);

            var matches = notary.documentMatches(result.document, result.citation);
            expect(matches).to.equal(true);
            notaryCertificate = newNotaryCertificate;
        });

    });

    describe('Test Multiple Notarizations', function() {

        it('should notarized a component twice properly', function() {
            var result = notary.notarizeComponent(component);
            var document = result.document;
            var citation = result.citation;
            var isValid = notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(true);
            var matches = notary.documentMatches(document, citation);
            expect(matches).to.equal(true);

            result = notary.notarizeComponent(document);
            document = result.document;
            citation = result.citation;
            isValid = notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(true);
            matches = notary.documentMatches(document, citation);
            expect(matches).to.equal(true);
        });

    });

});
