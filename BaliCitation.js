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
var V1 = require('./protocols/V1').V1;


exports.fromSource = function(source) {
    var document = bali.parseDocument(source);
    var protocol = bali.getStringForKey(document, '$protocol');
    var tag = bali.getStringForKey(document, '$tag');
    var version = bali.getStringForKey(document, '$version');
    var digest = bali.getStringForKey(document, '$digest');
    var citation = new BaliCitation(protocol, tag, version, digest);
    return citation;
};


exports.fromReference = function(reference) {
    var source = reference.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var catalog = bali.parseComponent(source);
    var protocol = bali.getStringForKey(catalog, '$protocol');
    var tag = bali.getStringForKey(catalog, '$tag');
    var version = bali.getStringForKey(catalog, '$version');
    var digest = bali.getStringForKey(catalog, '$digest');
    var citation = new BaliCitation(protocol, tag, version, digest);
    return citation;
};


function BaliCitation(protocol, tag, version, digest) {
    this.protocol = protocol;
    this.tag = tag;
    this.version = version;
    this.digest = digest;
    return this;
}
BaliCitation.prototype.constructor = BaliCitation;


BaliCitation.prototype.toString = function() {
    var source = V1.CITATION_TEMPLATE;
    source = source.replace(/%protocol/, this.protocol);
    source = source.replace(/%tag/, this.tag);
    source = source.replace(/%version/, this.version);
    source = source.replace(/%digest/, this.digest);
    return source;
};


BaliCitation.prototype.toReference = function() {
    var reference = V1.REFERENCE_TEMPLATE;
    reference = reference.replace(/%protocol/, this.protocol);
    reference = reference.replace(/%tag/, this.tag);
    reference = reference.replace(/%version/, this.version);
    reference = reference.replace(/%digest/, this.digest);
    return reference;
};
