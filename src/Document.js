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
 * This composite class captures the state and methods associated with a Bali document.
 */
var bali = require('bali-component-framework');


// PUBLIC FUNCTIONS

/**
 * This constructor creates a new Bali document using the specified optional previous
 * version reference and the content of the document. The new document is not yet
 * notarized with any digital signatures.
 * 
 * @param {String|Reference} previousReference An optional reference to the previous version of the
 * document.
 * @param {Component} documentContent The content of the document.
 * @returns {Document} The new Bali document.
 */
function Document(previousReference, documentContent) {
    previousReference = previousReference || bali.Template.NONE;
    if (previousReference.constructor.name === 'String') {
        previousReference = new bali.Reference(previousReference);
    }
    this.previousReference = previousReference;
    this.documentContent = documentContent;
    this.notarySeals = new bali.List();
    return this;
}
Document.prototype.constructor = Document;
exports.Document = Document;

Document.DIVIDER = '\n-----\n';

Document.fromString = function(source) {
    var parts = source.split(Document.DIVIDER);
    var documentContent = bali.parser.parseComponent(parts[0]);
    var previousReference = (parts[1] === 'none') ? bali.Template.NONE : new bali.Reference(parts[1]);
    var document = new Document(previousReference, documentContent);
    for (var i = 2; i < parts.length; i++) {
        var seal = parts[i];
        var index = seal.indexOf('\n');
        var certificateReference = new bali.Reference(seal.slice(0, index));
        var digitalSignature = new bali.Binary(seal.slice(index + 1));
        document.addNotarySeal(certificateReference, digitalSignature);
    }
    return document;
};


// PUBLIC METHODS

Document.prototype.toString = function() {
    var string = '';
    string += this.documentContent;
    string += Document.DIVIDER;
    string += this.previousReference;
    var iterator = this.notarySeals.getIterator();
    while (iterator.hasNext()) {
        var seal = iterator.getNext();
        string += Document.DIVIDER;
        string += seal.getValue('$certificateReference') + '\n';
        string += seal.getValue('$digitalSignature');
    }
    return string;
};


/**
 * This function returns a (deep) copy of the document.
 * 
 * @returns {Document} A deep copy of the document.
 */
Document.prototype.exactCopy = function() {
    var source = this.documentContent.toSource();
    var content = bali.parser.parseComponent(source);
    var copy = new Document(this.previousReference, content);
    copy.notarySeals = bali.List.fromCollection(this.notarySeals);
    return copy;
};


/**
 * This function returns a copy of the document without its last notary seal.
 * 
 * @returns {Document} A copy of the document without the last seal.
 */
Document.prototype.unsealedCopy = function() {
    var copy = this.exactCopy();
    copy.notarySeals.removeItem(-1);  // remove the last notary seal
    return copy;
};


/**
 * This function returns a draft copy of the document. The previous version reference
 * and seals from the original document have been removed from the draft copy.
 * 
 * @param {String|Reference} previousReference A reference to the document.
 * @returns {Document} A draft copy of the document.
 */
Document.prototype.draftCopy = function(previousReference) {
    var source = this.documentContent.toSource();
    var content = bali.parser.parseComponent(source);
    var draft = new Document(previousReference, content);
    return draft;
};


/**
 * This method sets the reference to the previous version of the document.
 * 
 * @param {String|Reference} previousReference The reference to the previous version of the document.
 */
Document.prototype.setPreviousReference = function(previousReference) {
    if (previousReference.constructor.name === 'String') {
        previousReference = new bali.Reference(previousReference);
    }
    this.previousReference = previousReference;
};


/**
 * This method returns the last notary seal on the document.
 * 
 * @returns {Seal} The last notary seal.
 */
Document.prototype.getLastSeal = function() {
    var notarySeal = this.notarySeals.getItem(-1);
    return notarySeal;
};


/**
 * This method appends a notary seal to the end of the document.
 * 
 * @param {String|Reference} certificateReference A reference to the certificate that can be
 * used to verify the associated digital signature.
 * @param {String|Binary} digitalSignature A base 32 encoded binary string containing the
 * digital signature generated using the notary key associated with the notary certificate
 * referenced by the certificate reference.
 */
Document.prototype.addNotarySeal = function(certificateReference, digitalSignature) {
    var notarySeal = new bali.Catalog();
    notarySeal.setValue('$certificateReference', certificateReference);
    notarySeal.setValue('$digitalSignature', digitalSignature);
    this.notarySeals.addItem(notarySeal);
};


/**
 * This function retrieves from a document the value associated with the
 * specified key.
 * 
 * @param {String|Number|Boolean|Component} key The key for the desired value.
 * @returns {Component} The value associated with the key.
 */
Document.prototype.getValue = function(key) {
    return this.documentContent.getValue(key);
};


/**
 * This function sets in a document a value associated with the
 * specified key.
 * 
 * @param {String|Number|Boolean|Component} key The key for the new value.
 * @param {String|Component} value The value to be associated with the key.
 * @returns {Component} The old value associated with the key.
 */
Document.prototype.setValue = function(key, value) {
    var oldValue = this.documentContent.setValue(key, value);
    return oldValue;
};


/**
 * This function removes from a document the value associated with the
 * specified key.
 * 
 * @param {String|Number|Boolean|Component} key The key for the value to be removed.
 * @returns {Component} The value associated with the key.
 */
Document.prototype.removeValue = function(key) {
    var oldValue = this.documentContent.removeValue(key);
    return oldValue;
};
