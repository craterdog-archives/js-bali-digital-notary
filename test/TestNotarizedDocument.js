/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

const fs = require('fs');
const mocha = require('mocha');
const expect = require('chai').expect;
const bali = require('bali-component-framework');
const NotarizedDocument = require('../src/NotarizedDocument').NotarizedDocument;

describe('Bali Digital Notary™', function() {
    var file = 'test/source/document.bali';
    var source = fs.readFileSync(file, 'utf8');
    expect(source).to.exist;  // jshint ignore:line
    var document = NotarizedDocument.fromString(source);

    describe('Test Document Creation', function() {

        it('should parse and format a notarized document', function() {
            expect(document).to.exist;  // jshint ignore:line
            var formatted = document.toString();
            //fs.writeFileSync(file, formatted, 'utf8');
            expect(formatted).to.equal(source);
        });

    });

});
