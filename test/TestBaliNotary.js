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
var bali = require('bali-document-notation');
var notary = require('../src/BaliNotary').notaryKey('test/config/');
var V1 = require('../src/v1/V1');

describe('Bali Digital Notary™', function() {

    var notaryCertificate = notary.generateKeys();
    var certificateCitation = notary.getNotaryCitation();
    var source = '[$foo: "bar"]\n';

    describe('Test Citations', function() {

        it('should validate the citation for the certificate', function() {
            expect(notaryCertificate.equalTo(notary.getNotaryCertificate())).to.equal(true);
            var protocol = notaryCertificate.getValue('$protocol');
            expect(protocol.toSource()).to.equal('v1');
            var isValid = notary.documentMatches(certificateCitation, notaryCertificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', function() {
            var tag = new bali.Tag();
            var version = new bali.Version('v2.3.4');
            var document = bali.parser.parseDocument(source);
            var documentCitation = notary.notarizeDocument(tag, version, document);
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
            var tag = new bali.Tag();
            var version = new bali.Version('v2.3.4');
            var document = bali.parser.parseDocument(source);
            notary.notarizeDocument(tag, version, document);

            var newCertificate = notary.generateKeys();
            expect(notaryCertificate).to.exist;  // jshint ignore:line

            document = bali.parser.parseDocument(source);
            var newDocumentCitation = notary.notarizeDocument(tag, version, document);
            isValid = notary.documentIsValid(notaryCertificate, document);
            expect(isValid).to.equal(false);

            isValid = notary.documentIsValid(newCertificate, document);
            expect(isValid).to.equal(true);

            var matches = notary.documentMatches(newDocumentCitation, document);
            expect(matches).to.equal(true);
        });

    });

});
