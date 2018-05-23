/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

var notary = require('../BaliNotary');
var forge = require('node-forge');
var mocha = require('mocha');
var expect = require('chai').expect;

describe('Bali Digital Notary™', function() {

    describe('Test Hashing and Signing', function() {

        it('should hash a random byte array properly', function() {
            for (var i = 0; i < 33; i++) {
                var bytes = forge.random.getBytesSync(i);
                expect(bytes).to.exist;  // jshint ignore:line
                var length = bytes.length;
                var expected = i;
                expect(length).to.equal(expected);
                var hash = notary.sha512Hash(bytes);
                expect(hash).to.exist;  // jshint ignore:line
                length = hash.length;
                expected = 64;
                expect(length).to.equal(expected);
            }
        });

        it('should digitally sign a random byte array properly', function() {
            var keyPair = notary.generateKeyPair();
            expect(keyPair).to.exist;  // jshint ignore:line
            var publicKey = keyPair.publicKey;
            expect(publicKey).to.exist;  // jshint ignore:line
            var privateKey = keyPair.privateKey;
            expect(privateKey).to.exist;  // jshint ignore:line
            for (var i = 0; i < 10; i++) {
                var bytes = forge.random.getBytesSync(i);
                expect(bytes).to.exist;  // jshint ignore:line
                var signatureBytes = notary.signString(privateKey, bytes);
                expect(signatureBytes).to.exist;  // jshint ignore:line
                var isValid = notary.signatureIsValid(publicKey, bytes, signatureBytes);
                expect(isValid).to.equal(true);
            }
        });

    });

});
