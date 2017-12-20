/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/
'use strict';
var notary = require('../BaliNotary');
var forge = require('node-forge');
var testCase = require('nodeunit').testCase;


module.exports = testCase({
    'Test SHA512 Hash': function(test) {
        test.expect(66);
        for (var i = 0; i < 33; i++) {
            var bytes = forge.random.getBytesSync(i);
            var length = bytes.length;
            var expected = i;
            test.strictEqual(length, expected, 'The length of the random string is wrong: ' + length);
            var hash = notary.sha512Hash(bytes);
            length = hash.length;
            expected = 64;
            test.strictEqual(length, expected, 'The length of the hash string is wrong: ' + length);
        }
        test.done();
    },
    'Test Signatures': function(test) {
        var keyPair = notary.generateKeyPair();
        var publicKey = keyPair.publicKey;
        var privateKey = keyPair.privateKey;
        test.expect(10);
        for (var i = 0; i < 10; i++) {
            var bytes = forge.random.getBytesSync(i);
            var signatureBytes = notary.signString(privateKey, bytes);
            var isValid = notary.signatureIsValid(publicKey, bytes, signatureBytes);
            test.ok(isValid, 'The signature is not valid.');
        }
        test.done();
    }
});
