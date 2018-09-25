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

/*
 * This module defines a class containing the attributes associated with a Bali
 * Document Citation™. A document citation references a Bali document in a way
 * that prevents the document from being tampered with. The citation contains a
 * digest attribute that is derived from the document content and can be
 * regenerated when the document is retrieved to compare the digest values. They
 * must be the same for the document to be considered valid.
 */
var BaliDocument = require('bali-document-notation/BaliDocument');
var codex = require('bali-document-notation/utilities/EncodingUtilities');
var V1 = require('./protocols/V1');


exports.fromScratch = function() {
    var protocol = V1.PROTOCOL;
    var tag = codex.randomTag();
    var version = 'v1';
    var digest = 'none';
    var citation = new BaliCitation(protocol, tag, version, digest);
    return citation;
};


exports.fromSource = function(source) {
    var document = BaliDocument.fromSource(source);
    var protocol = document.getString('$protocol');
    var tag = document.getString('$tag');
    var version = document.getString('$version');
    var digest = document.getString('$digest').replace(/\s/g, '');
    var citation = new BaliCitation(protocol, tag, version, digest);
    return citation;
};


exports.fromReference = function(reference) {
    reference = reference.toString();
    var source = reference.slice(6, -1);  // remove '<bali:' and '>' wrapper
    var document = BaliDocument.fromSource(source);
    var protocol = document.getString('$protocol');
    var tag = document.getString('$tag');
    var version = document.getString('$version');
    var digest = document.getString('$digest').replace(/\s/g, '');
    var citation = new BaliCitation(protocol, tag, version, digest);
    return citation;
};


function BaliCitation(protocol, tag, version, digest) {
    this.protocol = protocol;
    this.tag = tag;
    this.version = version;
    this.digest = digest.replace(/\s/g, '');
    return this;
}
BaliCitation.prototype.constructor = BaliCitation;


BaliCitation.prototype.toString = function() {
    var source = this.toSource();
    return source;
};


BaliCitation.prototype.toReference = function() {
    var reference = '<bali:[$protocol:%protocol,$tag:%tag,$version:%version,$digest:%digest]>';
    reference = reference.replace(/%protocol/, this.protocol);
    reference = reference.replace(/%tag/, this.tag);
    reference = reference.replace(/%version/, this.version);
    reference = reference.replace(/%digest/, this.digest);
    return reference;
};


BaliCitation.prototype.toSource = function(indentation) {
    indentation = indentation ? indentation : '';
    var source =  '[\n' +
        indentation + '    $protocol: %protocol\n' +
        indentation + '    $tag: %tag\n' +
        indentation + '    $version: %version\n' +
        indentation + '    $digest: %digest\n' +
        indentation + ']\n';
    source = source.replace(/%protocol/, this.protocol);
    source = source.replace(/%tag/, this.tag);
    source = source.replace(/%version/, this.version);
    source = source.replace(/%digest/, this.digest);
    return source;
};
