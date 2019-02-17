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
 *   .-------------------------------------------------------------------------------..
 *   | (A) The Digital Signature of Parts B, C, and D                                | \
 *   | (B) A Document Citation for the Public Certificate of the Signer (A)          |  Notary Seal
 *   | (C) A Document Citation for the Previous Version of the Document (or 'none')  | /
 *   |-------------------------------------------------------------------------------|'
 *   |                                                                               |
 *   | (D) The Content of the Document                                               |
 *   |                                                                               |
 *   '-------------------------------------------------------------------------------'
 * </pre>
 */
const bali = require('bali-component-framework');

// This private constant sets the POSIX end of line character
const EOL = '\n';


// PUBLIC FUNCTIONS

/**
 * This constructor creates a new notarized document using the specified parameters.
 * 
 * @param {Component} content The content of the document.
 * @param {Catalog} previous A document citation for the previous version of the document.
 * @param {Catalog} certificate A document citation for the public certificate for the
 * notary key that notarized the document.
 * @param {Binary} signature A base 32 encoded binary string containing the digital
 * signature of the document.
 * @returns {NotarizedDocument} The new notarized document.
 */
function NotarizedDocument(content, previous, certificate, signature) {
    this.content = content;
    this.certificate = certificate;
    this.previous = previous;
    this.signature = signature;
    return this;
}
NotarizedDocument.prototype.constructor = NotarizedDocument;
exports.NotarizedDocument = NotarizedDocument;

NotarizedDocument.fromString = function(string) {
    try {
        var index = 0;

        // extract the digital signature (A)
        const signature = parse(string);
        index += signature.toString().length + 1;

        // extract the public certificate citation (B)
        const certificate = parse(string.slice(index));
        index += certificate.toString().length + 1;

        // extract the previous document citation (C)
        const previous = parse(string.slice(index));
        index += previous.toString().length + 1;

        // extract the document content (D)
        const content = parse(string.slice(index));

        // construct the notarized document
        const document = new NotarizedDocument(content, previous, certificate, signature);
        return document;
    } catch (e) {
        throw bali.exception({
            $exception: '$invalidDocument',
            $document: '"' + EOL + string + EOL + '"',  // force the document to be a text block
            $message: '"' + EOL + 'The notarized document is invalid: ' + EOL + e + EOL + '"'
        });
    }
};


// PUBLIC METHODS

NotarizedDocument.prototype.toString = function() {
    var string = '';
    string += this.signature + EOL;
    string += this.certificate + EOL;
    string += this.previous + EOL;
    string += this.content;
    return string;
};


// PRVIATE FUNCTIONS

const parse = function(component) {
    const parser = new bali.Parser();
    return parser.parseComponent(component);
};
