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

/**
 * This class captures the state and methods associated with a notarized document.
 * 
 * All notarized documents have the following structure:
 * <pre>
 *   .---------------------------------------------------------------------------..
 *   | (A) A Digital Signature of Parts B, C, and D                              | \
 *   | (B) A Citation Reference to the Public Certificate of the Signer (A)      |  Notary Seal
 *   | (C) A Citation Reference to Previous Version of the Document (or 'none')  | /
 *   |---------------------------------------------------------------------------|'
 *   |                                                                           |
 *   | (D) The Content of the Document                                           |
 *   |                                                                           |
 *   '---------------------------------------------------------------------------'
 * </pre>
 */
var bali = require('bali-component-framework');


// PUBLIC FUNCTIONS

/**
 * This constructor creates a new notarized document using the specified parameters.
 * 
 * @param {String} content The content of the document.
 * @param {Reference} previousReference A reference to the previous version of the document.
 * @param {Reference} certificateReference A reference to the public certificate for the
 * notary key that notarized the document.
 * @param {Binary} digitalSignature A base 32 encoded binary string containing the digital
 * signature of the document.
 * @returns {NotarizedDocument} The new notarized document.
 */
function NotarizedDocument(content, previousReference, certificateReference, digitalSignature) {
    this.content = content.toString();  // force anything else to be a string
    this.certificateReference = certificateReference;
    this.previousReference = previousReference;
    this.digitalSignature = digitalSignature;
    return this;
}
NotarizedDocument.prototype.constructor = NotarizedDocument;
exports.NotarizedDocument = NotarizedDocument;

NotarizedDocument.fromString = function(string) {
    var document;
    try {
        var lines = string.split('\n');
        var binary = lines[0];
        for (var i = 1; i < 6; i++) {
            binary += '\n' + lines[i];
        }
        var digitalSignature = new bali.Binary(binary);
        var certificateReference = new bali.Reference(lines[6]);
        var previousReference = bali.Template.NONE;
        if (lines[7] !== 'none') {
            previousReference = new bali.Reference(lines[7]);
        }
        var content = lines[8];
        for (var j = 9; j < lines.length; j++) {
            content += '\n' + lines[j];
        }
        document = new NotarizedDocument(content, previousReference, certificateReference, digitalSignature);
    } catch (e) {
        throw new Error('DOCUMENT: An invalid notarized document string was found: ' + string);
    }
    return document;
};


// PUBLIC METHODS

NotarizedDocument.prototype.toString = function() {
    var string = '';
    string += this.digitalSignature + '\n';
    string += this.certificateReference + '\n';
    string += this.previousReference + '\n';
    string += this.content;
    return string;
};
