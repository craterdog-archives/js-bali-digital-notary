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
    var component = bali.parse('[$foo: "bar"]($tag: #MFPCRNKS2SG20CD7VQ6KD329X7382KJY, $version: v1)');

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
            notaryCertificate = certificateDocument.getValue('$component');
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
            const tag = bali.tag();
            const transaction = bali.catalog({
                $transactionId: bali.tag(),
                $timestamp: bali.moment(),
                $consumer: bali.text('Derk Norton'),
                $merchant: bali.reference('https://www.starbucks.com/'),
                $amount: 4.95
            }, bali.parameters({
                $tag: tag,
                $version: bali.version([2.4]),
            }));
            const previous = bali.catalog({
                $protocol: bali.version(),
                $tag: tag,
                $version: bali.version([2.3]),
                $digest: bali.parse("'JB2NG73VTB957T9TZWT44KRZVQ467KWJ2MSJYT6YW2RQAYQMSR861XGM5ZCDCPNJYR612SJT9RFKHA9YZ5DJMLYC7N3127AY4QDVJ38'")
            });
            var document = notary.notarizeDocument(transaction, previous);
            var citation = notary.citeDocument(document);
            var isValid = notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(true);
            var matches = notary.documentMatches(document, citation);
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
            var newCertificateDocument = notary.generateKeys();
            expect(newCertificateDocument).to.exist;  // jshint ignore:line
            var newNotaryCertificate = newCertificateDocument.getValue('$component');

            var document = notary.notarizeDocument(component);
            var citation = notary.citeDocument(document);
            isValid = notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(false);

            isValid = notary.documentIsValid(document, newNotaryCertificate);
            expect(isValid).to.equal(true);

            var matches = notary.documentMatches(document, citation);
            expect(matches).to.equal(true);
            notaryCertificate = newNotaryCertificate;
        });

    });

    describe('Test Multiple Notarizations', function() {

        it('should notarized a component twice properly', function() {
            var document = notary.notarizeDocument(component);
            var citation = notary.citeDocument(document);
            var isValid = notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(true);
            var matches = notary.documentMatches(document, citation);
            expect(matches).to.equal(true);

            document = notary.notarizeDocument(document);
            citation = notary.citeDocument(document);
            isValid = notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(true);
            matches = notary.documentMatches(document, citation);
            expect(matches).to.equal(true);
        });

    });

});
