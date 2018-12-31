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
 * This class captures the state and methods associated with a Bali Notarized Document™.
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
const bali = require('bali-component-framework');


// PUBLIC FUNCTIONS

/**
 * This constructor creates a new notarized document using the specified parameters.
 * 
 * @param {String} content The content of the document.
 * @param {Reference} previous A reference to the previous version of the document.
 * @param {Reference} certificate A reference to the public certificate for the
 * notary key that notarized the document.
 * @param {Binary} signature A base 32 encoded binary string containing the digital
 * signature of the document.
 * @returns {NotarizedDocument} The new notarized document.
 */
function NotarizedDocument(content, previous, certificate, signature) {
    this.content = content.toString();  // force anything else to be a string
    this.certificate = certificate;
    this.previous = previous;
    this.signature = signature;
    return this;
}
NotarizedDocument.prototype.constructor = NotarizedDocument;
exports.NotarizedDocument = NotarizedDocument;

NotarizedDocument.fromString = function(string) {
    var document;
    try {
        var lines = string.split('\n');

        // extract the digital signature (A)
        var binary = lines.slice(0, 4).join('\n');
        var signature = new bali.Binary(binary);

        // extract the public certificate reference (B)
        var certificate = new bali.Reference(lines[4]);

        // extract the previous document reference (C)
        var previous = bali.Filter.NONE;
        if (lines[5] !== 'none') {
            previous = new bali.Reference(lines[5]);
        }

        // extract the document content (D)
        var content = lines.slice(6).join('\n');

        // construct the notarized document
        document = new NotarizedDocument(content, previous, certificate, signature);
    } catch (e) {
        throw new Error('NOTARY: An invalid notarized document string was found: ' + string);
    }
    return document;
};


// PUBLIC METHODS

NotarizedDocument.prototype.toString = function() {
    var string = '';
    string += this.signature + '\n';
    string += this.certificate + '\n';
    string += this.previous + '\n';
    string += this.content;
    return string;
};
