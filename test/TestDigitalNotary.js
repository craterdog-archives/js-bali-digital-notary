/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

var notary = require('../DigitalNotary');
var forge = require('node-forge');
var mocha = require('mocha');
var expect = require('chai').expect;

describe('Bali Digital Notary™', function() {

    var notaryKey = new notary.NotaryKey();

    describe('Test Hashing', function() {

        it('should hash a random byte array properly', function() {
            for (var i = 0; i < 33; i++) {
                var bytes = forge.random.getBytesSync(i);
                expect(bytes).to.exist;  // jshint ignore:line
                var length = bytes.length;
                var expected = i;
                expect(length).to.equal(expected);
                var hash = notary.generateHash(bytes);
                expect(hash).to.exist;  // jshint ignore:line
                length = hash.length;
                expected = 64;
                expect(length).to.equal(expected);
            }
        });

    });

    describe('Test Signing and Verification', function() {

        it('should digitally sign a random byte array properly', function() {
            var certificate = notaryKey.certificate;
            var message = '';
            for (var i = 0; i < 100; i++) {
                message += i;
            }
            expect(message).to.exist;  // jshint ignore:line
            var seal = notaryKey.generateSeal(message);
            expect(seal).to.exist;  // jshint ignore:line
            var isValid = certificate.sealIsValid(message, seal);
            expect(isValid).to.equal(true);
        });

    });

    describe('Test Encryption and Decryption', function() {

        it('should encrypt and decrypt a key properly', function() {
            var certificate = notaryKey.certificate;
            var message = 'This is a test...';
            var encrypted = certificate.encryptMessage(message);
            var decrypted = notaryKey.decryptMessage(encrypted);
            expect(decrypted).to.equal(message);
        });

    });

    describe('Test Exporting and Importing of Keys', function() {

        it('should export and re-import a key pair properly', function() {
            var certificate = notaryKey.certificate;
            var message = 'This is a test...';
            var seal = notaryKey.generateSeal(message);
            var exported = certificate.exportPem();
            certificate = new notary.NotaryCertificate(exported);
            var isValid = certificate.sealIsValid(message, seal);
            expect(isValid).to.equal(true);
            exported = notaryKey.exportPem();
            var newKey = new notary.NotaryKey(exported);
            var newSeal = newKey.generateSeal(message);
            isValid = certificate.sealIsValid(message, newSeal);
            expect(isValid).to.equal(true);
        });

    });

});
