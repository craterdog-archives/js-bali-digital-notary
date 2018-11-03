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
 * This composite class implements a digital notary seal. It is used by the document class.
 */
var bali = require('bali-component-framework');


// PUBLIC FUNCTIONS

/**
 * This constructor creates a new digital notary seal.
 * 
 * @param {String|Reference} certificateReference A reference to the certificate that can be
 * used to verify the associated digital signature.
 * @param {String|Binary} digitalSignature A base 32 encoded binary string containing the
 * digital signature generated using the notary key associated with the notary certificate
 * referenced by the certificate reference.
 * @returns {Association} A new digital notary seal.
 */
function Seal(certificateReference, digitalSignature) {
    if (certificateReference.constructor.name === 'String') {
        certificateReference = new bali.Reference(certificateReference);
    }
    if (digitalSignature.constructor.name === 'String') {
        digitalSignature = new bali.Binary(digitalSignature);
    }
    this.certificateReference = certificateReference;
    this.digitalSignature = digitalSignature;
    return this;
}
Seal.prototype.constructor = Seal;
exports.Seal = Seal;
