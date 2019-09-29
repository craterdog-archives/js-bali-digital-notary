/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

const debug = 0;  // set to [1..3] for logging at various levels
const crypto = require('crypto');
const mocha = require('mocha');
const assert = require('chai').assert;
const expect = require('chai').expect;
const bali = require('bali-component-framework').api(debug);
const account = bali.tag();
const directory = 'test/config/';
const api = require('../');
const securityModule = api.ssm(directory, debug);
const notary = api.notary(securityModule, account, directory, debug);


describe('Bali Digital Notary™', function() {

    var notaryCertificate;
    var certificateCitation;
    var component = bali.component('[$foo: "bar"]($tag: #MFPCRNKS2SG20CD7VQ6KD329X7382KJY, $version: v1, $permissions: /bali/permissions/public/v1, $previous: none)');

    describe('Test Key Generation', function() {

        it('should return the correct account tag', function() {
            expect(notary.getAccount().isEqualTo(account)).to.equal(true);
        });

        it('should return the protocols', function() {
            const protocols = notary.getProtocols();
            expect(protocols).to.exist;
        });

        it('should generate the keys', async function() {
            const catalog = await notary.generateKey();
            notaryCertificate = await notary.notarizeDocument(catalog);
            certificateCitation = await notary.activateKey(notaryCertificate);
            expect(notaryCertificate).to.exist;
        });

        it('should retrieve the certificate citation', async function() {
            certificateCitation = await notary.getCitation();
            expect(certificateCitation).to.exist;
        });

    });

    describe('Test Certificate Validation', function() {

        it('should validate the certificate', async function() {
            expect(notaryCertificate.getValue('$protocol').toString()).to.equal('v1');
            const certificate = notaryCertificate.getValue('$component');
            var isValid = await notary.validDocument(notaryCertificate, certificate);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', async function() {
            var isValid = await notary.citationMatches(certificateCitation, notaryCertificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', async function() {
            const tag = bali.tag();
            const previous = bali.catalog({
                $protocol: bali.version(),
                $timestamp: bali.component('<2019-02-24T22:41:18.843>'),
                $tag: tag,
                $version: bali.version([2, 3]),
                $digest: bali.component("'JB2NG73VTB957T9TZWT44KRZVQ467KWJ2MSJYT6YW2RQAYQMSR861XGM5ZCDCPNJYR612SJT9RFKHA9YZ5DJMLYC7N3127AY4QDVJ38'")
            }, {
                $type: bali.component('/bali/notary/Citation/v1')
            });
            const transaction = bali.catalog({
                $transactionId: bali.tag(),
                $timestamp: bali.moment(),
                $consumer: bali.text('Derk Norton'),
                $merchant: bali.reference('https://www.starbucks.com/'),
                $amount: 4.95
            }, {
                $type: bali.component('/acme/types/Transaction/v2.3'),
                $tag: tag,
                $version: bali.version([2, 4]),
                $permissions: bali.component('/bali/permissions/public/v1'),
                $previous: previous
            });
            var document = await notary.notarizeDocument(transaction);

            const certificate = notaryCertificate.getValue('$component');

            var citation = await notary.citeDocument(document);
            var isValid = await notary.validDocument(document, certificate);
            expect(isValid).to.equal(true);
            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Key Rotation', function() {

        it('should refresh a notary key properly', async function() {
            var newNotaryCertificate = await notary.refreshKey();
            expect(newNotaryCertificate).to.exist;

            const certificate = notaryCertificate.getValue('$component');
            const newCertificate = newNotaryCertificate.getValue('$component');

            var isValid = await notary.validDocument(newNotaryCertificate, certificate);
            expect(isValid).to.equal(true);

            var document = await notary.notarizeDocument(component);

            var citation = await notary.citeDocument(document);
            isValid = await notary.validDocument(document, certificate);
            expect(isValid).to.equal(false);

            isValid = await notary.validDocument(document, newCertificate);
            expect(isValid).to.equal(true);

            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);

            notaryCertificate = newNotaryCertificate;
        });

    });

    describe('Test Multiple Notarizations', function() {

        it('should notarized a component twice properly', async function() {
            var document = await notary.notarizeDocument(component);

            const certificate = notaryCertificate.getValue('$component');

            var citation = await notary.citeDocument(document);
            var isValid = await notary.validDocument(document, certificate);
            expect(isValid).to.equal(true);
            var matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);

            document = document.duplicate();
            document.setParameter('$tag', document.getValue('$component').getParameter('$tag')),
            document.setParameter('$version', bali.component('v2'));
            document.setParameter('$permissions', bali.component('/bali/permissions/public/v1'));
            document.setParameter('$previous', bali.pattern.NONE);
            document = await notary.notarizeDocument(document);

            citation = await notary.citeDocument(document);
            isValid = await notary.validDocument(document, certificate);
            expect(isValid).to.equal(true);
            matches = await notary.citationMatches(citation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Key Erasure', function() {

        it('should erase all keys properly', async function() {
            await notary.forgetKey();
            try {
                await notary.notarizeDocument(component);
                assert.fail('The attempt to sign a component without a key should have failed.');
            } catch (error) {
                // expected
            };
        });

    });

});
