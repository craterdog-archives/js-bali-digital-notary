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
const assert = require('chai').assert;
const expect = require('chai').expect;
const bali = require('bali-component-framework');
const account = bali.tag();
const notary = require('../').api(account, 'test/config/');

describe('Bali Digital Notary™', function() {

    var certificateDocument;
    var notaryCertificate;
    var certificateCitation;
    var component = bali.parse('[$foo: "bar"]($tag: #MFPCRNKS2SG20CD7VQ6KD329X7382KJY, $version: v1)');

    describe('Test Key Generation', function() {

        it('should initialize the API once and only once', async function() {
            await notary.initializeAPI();
            try {
                await notary.initializeAPI();
                assert.fail('The second attempt to initialize the API should have failed.');
            } catch(error) {
                // expected
            };
        });

        it('should support correct versions', async function() {
            const versions = await notary.supportedProtocols();
            expect(versions.toString()).to.equal('[v1]');
        });

        it('should generate the keys', async function() {
            certificateDocument = await notary.generateKeyPair();
            expect(certificateDocument).to.exist;  // jshint ignore:line
        });

        it('should retrieve the notary certificate', async function() {
            notaryCertificate = certificateDocument.getValue('$component');
            expect(notaryCertificate).to.exist;  // jshint ignore:line
        });

        it('should retrieve the certificate citation', async function() {
            certificateCitation = await notary.getCitation();
            expect(certificateCitation).to.exist;  // jshint ignore:line
        });

    });

    describe('Test Certificate Validation', function() {

        it('should validate the certificate', async function() {
            const certificate = await notary.getCertificate();
            expect(certificateDocument.toString()).to.equal(certificate.toString());
            expect(notaryCertificate.getValue('$protocol').toString()).to.equal('v1');
            var isValid = await notary.documentIsValid(certificateDocument, notaryCertificate);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', async function() {
            var isValid = await notary.citationMatches(certificateCitation, certificateDocument);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', async function() {
            const tag = bali.tag();
            const transaction = bali.catalog({
                $transactionId: bali.tag(),
                $timestamp: bali.moment(),
                $consumer: bali.text('Derk Norton'),
                $merchant: bali.reference('https://www.starbucks.com/'),
                $amount: 4.95
            }, bali.parameters({
                $tag: tag,
                $version: bali.version([2, 4])
            }));
            const previous = bali.catalog({
                $protocol: bali.version(),
                $timestamp: bali.parse('<2019-02-24T22:41:18.843>'),
                $tag: tag,
                $version: bali.version([2, 3]),
                $digest: bali.parse("'JB2NG73VTB957T9TZWT44KRZVQ467KWJ2MSJYT6YW2RQAYQMSR861XGM5ZCDCPNJYR612SJT9RFKHA9YZ5DJMLYC7N3127AY4QDVJ38'")
            });
            var document = await notary.notarizeDocument(transaction, previous);
            var citation = await notary.citeDocument(document);
            var isValid = await notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(true);
            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Encryption and Decryption', function() {

        it('should encrypt and decrypt a component properly', async function() {
            var component = bali.parse('"This is a test..."');
            var encrypted = await notary.encryptComponent(component, notaryCertificate);
            var decrypted = await notary.decryptComponent(encrypted);
            expect(decrypted.isEqualTo(component)).to.equal(true);
        });

    });

    describe('Test Key Regeneration', function() {

        it('should regenerate a notary key properly', async function() {
            var newCertificateDocument = await notary.generateKeyPair();
            expect(newCertificateDocument).to.exist;  // jshint ignore:line
            var newNotaryCertificate = newCertificateDocument.getValue('$component');

            var document = await notary.notarizeDocument(component);
            var citation = await notary.citeDocument(document);
            isValid = await notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(false);

            isValid = await notary.documentIsValid(document, newNotaryCertificate);
            expect(isValid).to.equal(true);

            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);
            notaryCertificate = newNotaryCertificate;
        });

    });

    describe('Test Multiple Notarizations', function() {

        it('should notarized a component twice properly', async function() {
            var document = await notary.notarizeDocument(component);
            var citation = await notary.citeDocument(document);
            var isValid = await notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(true);
            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);

            document = await notary.notarizeDocument(document);
            citation = await notary.citeDocument(document);
            isValid = await notary.documentIsValid(document, notaryCertificate);
            expect(isValid).to.equal(true);
            matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);
        });

    });

});
