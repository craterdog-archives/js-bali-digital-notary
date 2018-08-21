/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

var bali = require('bali-document-notation/BaliDocuments');
var codex = require('bali-document-notation/utilities/EncodingUtilities');
var notary = require('../BaliNotary').notary('test/config/');
var mocha = require('mocha');
var expect = require('chai').expect;

describe('Bali Digital Notary™', function() {

    var certificate = notary.generateKeys();
    var citation = notary.citation();
    var source =
            '[\n' +
            '    $foo: "bar"\n' +
            ']\n';

    describe('Test Citations', function() {

        it('should validate the citation for the certificate', function() {
            var protocol = bali.getStringForKey(certificate, '$protocol');
            var tag = bali.getStringForKey(certificate, '$tag');
            var version = bali.getStringForKey(certificate, '$version');
            expect(protocol).to.equal('v1');
            expect(tag).to.equal(citation.tag);
            expect(version).to.equal(citation.version);
            var isValid = notary.documentMatches(citation, certificate);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a document properly', function() {
            var tag = codex.randomTag();
            var version = 'v2.3.4';
            var document = bali.parseDocument(source);
            var documentCitation = notary.notarizeDocument(tag, version, document);
            var isValid = notary.documentIsValid(certificate, document);
            expect(isValid).to.equal(true);
            var matches = notary.documentMatches(documentCitation, document);
            expect(matches).to.equal(true);
        });

    });

    describe('Test Encryption and Decryption', function() {

        it('should encrypt and decrypt a message properly', function() {
            var message = 'This is a test...';
            var encrypted = notary.encryptMessage(certificate, message);
            var decrypted = notary.decryptMessage(encrypted);
            expect(decrypted).to.equal(message);
        });

    });

    describe('Test Key Regeneration', function() {

        it('should regenerate a notary key properly', function() {
            var tag = codex.randomTag();
            var version = 'v2.3.4';
            var document = bali.parseDocument(source);
            notary.notarizeDocument(tag, version, document);

            var newCertificate = notary.regenerateKeys();
            expect(certificate).to.exist;  // jshint ignore:line

            document = bali.parseDocument(source);
            var newDocumentCitation = notary.notarizeDocument(tag, version, document);
            isValid = notary.documentIsValid(certificate, document);
            expect(isValid).to.equal(false);

            isValid = notary.documentIsValid(newCertificate, document);
            expect(isValid).to.equal(true);

            var matches = notary.documentMatches(newDocumentCitation, document);
            expect(matches).to.equal(true);
        });

    });

});
