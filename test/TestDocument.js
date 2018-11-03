/************************************************************************
 * Copyright (c) Crater Dog Technologies(TM).  All Rights Reserved.     *
 ************************************************************************
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.        *
 *                                                                      *
 * This code is free software; you can redistribute it and/or modify it *
 * under the terms of The MIT License (MIT), as published by the Open   *
 * Source Initiative. (See http://opensource.org/licenses/MIT)          *
 ************************************************************************/

var fs = require('fs');
var mocha = require('mocha');
var expect = require('chai').expect;
var Document = require('../src/Document').Document;
var Seal = require('../src/Seal').Seal;

describe('Bali Document Notation™', function() {
    var file = 'test/source/document.bali';
    var source = fs.readFileSync(file, 'utf8');
    expect(source).to.exist;  // jshint ignore:line
    var document = Document.fromSource(source);

    describe('Test Document Creation', function() {

        it('should create a document from source', function() {
            expect(document).to.exist;  // jshint ignore:line
            var formatted = document.toString();
            //fs.writeFileSync(file, formatted, 'utf8');
            expect(formatted).to.equal(source);
        });

        it('should create a copy of a document', function() {
            document = document.exactCopy();
            expect(document).to.exist;  // jshint ignore:line
            var formatted = document.toString();
            expect(formatted).to.equal(source);
        });

        it('should create a draft of a document', function() {
            var draft = document.draftCopy(document.previousReference);
            expect(draft).to.exist;  // jshint ignore:line
            document.notarySeals = [];
            expect(draft.toString()).to.equal(document.toString());
            document = Document.fromSource(source);
        });

        it('should create an unsealed copy of a document', function() {
            var unsealed = document.unsealedCopy();
            expect(unsealed).to.exist;  // jshint ignore:line
            expect(unsealed.notarySeals.length).to.equal(1);
            expect(document.notarySeals[0].toString()).to.equal(unsealed.notarySeals[0].toString());
        });

    });

    describe('Test Document Catalog Access', function() {
        var key = '$foo';
        var value;

        it('should retrieve attribute values', function() {
            var stringValue = document.getValue(key).toString();
            value = document.getValue(key);
            expect(value).to.exist;  // jshint ignore:line
            expect(value.toString()).to.equal(stringValue);
        });

        it('should set new attribute values', function() {
            var newKey = '$new';
            var stringValue = value.toString();
            var oldValue = document.setValue(newKey, value);
            expect(oldValue).to.not.exist;  // jshint ignore:line
            value = document.getValue(newKey);
            expect(value).to.exist;  // jshint ignore:line
            expect(value.toString()).to.equal(stringValue);
        });

        it('should update attribute values', function() {
            var stringValue = '$bar';
            var oldValue = document.setValue(key, stringValue);
            expect(oldValue).to.exist;  // jshint ignore:line
            expect(oldValue.toString()).to.equal(value.toString());
            value = document.getValue(key);
            expect(value).to.exist;  // jshint ignore:line
            expect(value.toString()).to.equal(stringValue);
        });

        it('should remove attribute values', function() {
            var oldValue = document.removeValue(key);
            expect(oldValue).to.exist;  // jshint ignore:line
            expect(oldValue.isEqualTo(value)).to.equal(true);
        });

    });

    describe('Test Document Seal Access', function() {

        it('should retrieve the last notary seal', function() {
            var size = document.notarySeals.length;
            var lastSeal = document.getLastSeal();
            expect(lastSeal).to.exist;  // jshint ignore:line
            var expectedSeal = document.notarySeals[size - 1];
            expect(expectedSeal).to.exist;  // jshint ignore:line
            expect(lastSeal.toString()).to.equal(expectedSeal.toString());
        });

        it('should add a new notary seal', function() {
            var certificateReference = "<bali:[$protocol:v1,$tag:#4Z46DL76YDRSSYW6HNDVSL66XV69TTS6,$version:v1,$digest:'C3RXCMQ1YJH2TPP7CJNAHRW9JH103ZW8XC26KY47NNQKCF969GBS076NZ7G2DG18KLP5K55H4Q8GSSK1MJJYT5BZX8BMQ1WXDDWKSZH']>";
            var digitalSignature = "'\n" +
                    "    620RF0K2049Z3JCBCK512JWMNQVW5NLAL8Q3N76XKXCJ2HDKA44QPGFNTYTANX5XRS0FLHB4FDTMC69H\n" +
                    "    DYMVAKDQ0RLZF5RP25W8PRTVY45TCYZ7N0142PMAKPWSJT3LZC078VY2HH104826PP9XX56PCT0S0YT0\n" +
                    "    PLQGACSS3BCJX4JAWX892H71JL3HKXYSFSC78G7YM2DJKPYZXBCBLPBSJLN9Y\n" +
                    "'";
            var notarySeal = new Seal(certificateReference, digitalSignature);
            document.addNotarySeal(notarySeal);
            var seals = document.notarySeals;
            expect(seals).to.exist;  // jshint ignore:line
            expect(seals.length).to.equal(3);
        });

    });

});
