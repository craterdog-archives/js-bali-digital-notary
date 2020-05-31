/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

const debug = 0;  // set to [0..3] for logging at various levels
const crypto = require('crypto');
const mocha = require('mocha');
const chai = require('chai');
const expect = chai.expect;
const assert = require('assert');
const fs = require('fs');
const bali = require('bali-component-framework').api(debug);
const account = bali.tag();
const directory = 'test/config/';
const api = require('../');
const notary = api.test(account, directory, debug);
const service = api.service(debug);


describe('Bali Digital Notary™', function() {

    var certificate;
    var citation;
    const document = bali.catalog({
        $foo: 'bar'
    }, {
        $type: '/bali/examples/Content/v1',
        $tag: '#MFPCRNKS2SG20CD7VQ6KD329X7382KJY',
        $version: 'v1',
        $permissions: '/bali/permissions/public/v1',
        $previous: 'none'
    });
    const style = 'https://bali-nebula.net/static/styles/BDN.css';

    describe('Test Key Generation', function() {
        fs.mkdirSync('test/html', {recursive: true, mode: 0o700});

        it('should return the correct account tag', function() {
            expect(notary.getAccount().isEqualTo(account)).to.equal(true);
            expect(service.getAccount()).to.equal(undefined);
        });

        it('should return the protocols', function() {
            const protocols = notary.getProtocols();
            expect(protocols).to.exist;
            expect(protocols.isEqualTo(service.getProtocols())).to.equal(true);
        });

        it('should generate the keys', async function() {
            const publicKey = await notary.generateKey();
            certificate = await notary.notarizeDocument(publicKey);
            citation = await notary.activateKey(certificate);
            expect(certificate).to.exist;
            const html = certificate.toHTML(style) + '\n';  // add POSIX <EOL>
            fs.writeFileSync('test/html/certificate.html', html, 'utf8');
            await assert.rejects(async function() {
                await service.generateKey();
            });
        });

        it('should retrieve the certificate citation', async function() {
            citation = await notary.getCitation();
            expect(citation).to.exist;
            const html = citation.toHTML(style) + '\n';  // add POSIX <EOL>
            fs.writeFileSync('test/html/citation.html', html, 'utf8');
            await assert.rejects(async function() {
                await service.getCitation();
            });
        });

    });

    describe('Test Certificate Validation', function() {

        it('should validate the certificate', async function() {
            expect(certificate.getValue('$protocol').toString()).to.equal('v2');
            var isValid = await notary.validContract(certificate, certificate);
            expect(isValid).to.equal(true);
        });

        it('should validate the citation for the certificate', async function() {
            var isValid = await notary.citationMatches(citation, certificate.getValue('$document'));
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Credential Generation and Verification', function() {
        var credentials;

        it('should generate new credentials properly', async function() {
            const salt = bali.tag();
            credentials = await notary.generateCredentials(salt);
            expect(credentials).to.exist;
            const html = credentials.toHTML(style) + '\n';  // add POSIX <EOL>
            fs.writeFileSync('test/html/credentials.html', html, 'utf8');
        });

        it('should validate the credentials properly', async function() {
            const isValid = await notary.validContract(credentials, certificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Citations', function() {
        var contract, citation;
        const tag = bali.tag();
        const previous = bali.catalog({
            $protocol: 'v1',
            $tag: tag,
            $version: 'v2.3',
            $digest: "'JB2NG73VTB957T9TZWT44KRZVQ467KWJ2MSJYT6YW2RQAYQMSR861XGM5ZCDCPNJYR612SJT9RFKHA9YZ5DJMLYC7N3127AY4QDVJ38'"
        }, {
            $type: bali.component('/bali/notary/Citation/v1')
        });
        const transaction = bali.catalog({
            $transactionId: bali.tag(),
            $timestamp: bali.moment(),
            $consumer: 'Derk Norton',
            $merchant: bali.reference('https://www.starbucks.com/'),
            $amount: 4.95
        }, {
            $type: '/acme/types/Transaction/v2.3',
            $tag: tag,
            $version: 'v2.4',
            $permissions: '/bali/permissions/public/v1',
            $previous: previous
        });

        it('should cite a document properly', async function() {
            citation = await service.citeDocument(transaction);
            expect(citation).to.exist;
        });

        it('should validate the citation properly', async function() {
            var matches = await service.citationMatches(citation, transaction);
            expect(matches).to.equal(true);
        });

        it('should notarize a document properly', async function() {
            contract = await notary.notarizeDocument(transaction);
            const html = contract.toHTML(style) + '\n';  // add POSIX <EOL>
            fs.writeFileSync('test/html/contract.html', html, 'utf8');
            await assert.rejects(async function() {
                await service.notarizeDocument(transaction);
            });
        });

        it('should validate the contract properly', async function() {
            var isValid = await service.validContract(contract, certificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Key Rotation', function() {

        it('should refresh a notary key properly', async function() {
            var newCertificate = await notary.refreshKey();
            expect(newCertificate).to.exist;
            const html = newCertificate.toHTML(style) + '\n';  // add POSIX <EOL>
            fs.writeFileSync('test/html/certificateV2.html', html, 'utf8');

            await assert.rejects(async function() {
                await service.refreshKey();
            });

            var isValid = await notary.validContract(newCertificate, certificate);
            expect(isValid).to.equal(true);

            const contract = await notary.notarizeDocument(document);

            isValid = await notary.validContract(contract, certificate);
            expect(isValid).to.equal(false);

            isValid = await notary.validContract(contract, newCertificate);
            expect(isValid).to.equal(true);

            certificate = newCertificate;
        });

    });

    describe('Test Multiple Notarizations', function() {

        it('should notarized a document twice properly', async function() {
            var contract = await notary.notarizeDocument(document);

            var isValid = await notary.validContract(contract, certificate);
            expect(isValid).to.equal(true);

            const copy = document.duplicate();
            copy.setParameter('$tag', document.getParameter('$tag')),
            copy.setParameter('$version', 'v2');
            copy.setParameter('$permissions', '/bali/permissions/public/v1');
            copy.setParameter('$previous', 'none');
            contract = await notary.notarizeDocument(copy);

            isValid = await notary.validContract(contract, certificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Key Erasure', function() {

        it('should erase all keys properly', async function() {
            await notary.forgetKey();
            await assert.rejects(async function() {
                await notary.notarizeDocument(document);
            });
        });

    });

});
