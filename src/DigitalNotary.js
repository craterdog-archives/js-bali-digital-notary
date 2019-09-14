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
 * This class implements a digital notary that is capable of performing the following functions:
 * <pre>
 *   * generateKey - generate a new notary key and return the associated notary certificate
 *   * activateKey - digitally notarize the notary certificate and return a citation to it
 *   * citeDocument - create a document citation for a document
 *   * citationMatches - check whether or not the digest for a citation matches the cited document
 *   * notarizeDocument - digitally notarize a document and return the notarized document
 *   * documentValid - check whether or not the notary seal on a notarized document is valid
 *   * rotateKey - replace the existing notary key with new one
 *   * forgetKey - forget any knowledge of the notary key
 * </pre>
 * All cryptographic operations are delegated to a security module.
 */
const bali = require('bali-component-framework').api();
const SSMv1 = require('./v1/SSM').SSM;
//const SSMv2 = require('./v2/SSM').SSM;
//const SSMv3 = require('./v3/SSM').SSM;
const EOL = '\n'; // The POSIX end of line character

// import the supported public API protocols (in preferred order)
const protocols = {
//  ...
//  v3: new SSMv3(),
//  v2: new SSMv2(),
    v1: new SSMv1()
};
const PROTOCOL = Object.keys(protocols)[0];  // the latest protocol


// PUBLIC API

/**
 * This function creates a new digital notary object.
 *
 * @param {Object} securityModule An object that implements the security module interface.
 * @param {Tag} account A unique account tag for the owner of the digital notary.
 * @param {String} directory An optional directory to be used for local configuration storage. If
 * no directory is specified, a directory called '.bali/' is created in the home directory.
 * @param {Boolean|Number} debug An optional number in the range [0..3] that controls
 * the level of debugging that occurs:
 * <pre>
 *   0 (or false): debugging turned off
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} An object that implements the API for a digital notary.
 */
function DigitalNotary(securityModule, account, directory, debug) {
    // validate the argument types
    if (debug === null || debug === undefined) debug = 0;  // default is off
    if (debug > 1) {
        const validator = bali.validator(debug);
        validator.validateType('/bali/notary/DigitalNotary', '$DigitalNotary', '$securityModule', securityModule, [
            '/javascript/Object'
        ]);
        validator.validateType('/bali/notary/DigitalNotary', '$DigitalNotary', '$account', account, [
            '/bali/elements/Tag'
        ]);
        validator.validateType('/bali/notary/DigitalNotary', '$DigitalNotary', '$directory', directory, [
            '/javascript/Undefined',
            '/javascript/String'
        ]);
    }

    // validate the argument values
    if (account) validateArgument('$privateAPI', 'account', account, 'tag');
    if (directory) validateArgument('$privateAPI', 'directory', directory);

    // define the private state
    var tag;
    var version;
    var timestamp;
    var publicKey;
    var citation;
    var configuration = bali.configuration(account.getValue() + '.bali', directory, debug);
    var automaton = bali.automaton(
        [              '$generateKey', '$activateKey', '$rotateKey', '$forgetKey', '$getCitation', '$citeDocument', '$citationMatches', '$notarizeDocument', '$documentValid' ],
        {
            $keyless: [ '$pending',      undefined,      undefined,   '$keyless',     undefined,     '$keyless',        '$keyless',          undefined,         '$keyless'    ],
            $pending: [  undefined,     '$enabled',      undefined,   '$keyless',     undefined,     '$pending',        '$pending',         '$pending',         '$pending'    ],
            $enabled: [  undefined,      undefined,     '$enabled',   '$keyless',    '$enabled',     '$enabled',        '$enabled',         '$enabled',         '$enabled'    ]
        }
    );

    /**
     * This function returns a string providing attributes about this digital notary API.
     *
     * @returns {String} A string providing attributes about this digital notary API.
     */
    this.toString = function() {
        const catalog = bali.catalog({
            $module: '/bali/notary/DigitalNotary',
            $protocol: PROTOCOL,
            $account: account || bali.pattern.NONE,
            $certificate: citation || bali.pattern.NONE
        });
        return catalog.toString();
    };

    /**
     * This function returns a list of the protocol versions supported by this digital notary
     * API.
     * 
     * @returns {List} A list of the protocol versions supported by this digital notary API.
     */
    this.getProtocols = function() {
        try {
            return bali.list(Object.keys(protocols));
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$getProtocols',
                $exception: '$unexpected',
                $text: bali.text('An unexpected error occurred while attempting to retrieve the supported security protocols.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };
   

    /**
     * This function returns the unique tag for the account that is associated with this
     * digital notary.
     * 
     * @returns {Tag} The unique tag for the account that is associated with this digital
     * notary.
     */
    this.getAccount = function() {
        return account;
    };


    /**
     * This function generates a new public-private key pair and uses the private key as the
     * new notary key. It returns the new public notary certificate. Note, during key rotation
     * the old private key is used to sign the new certificate before it is destroyed.
     *
     * @returns {Catalog} The new notary certificate.
     */
    this.generateKey = async function() {
        try {
            // check current state
            automaton.validateEvent('$generateKey');

            // generate a new public-private key pair
            citation = undefined;
            publicKey = bali.binary(await securityModule.generateKeys());
            timestamp = bali.moment();  // now
            tag = bali.tag();  // generate a new random tag
            version = bali.version();

            // create the new notary certificate
            const certificate = bali.catalog({
                $protocol: PROTOCOL,
                $timestamp: timestamp,
                $account: account,
                $publicKey: publicKey
            }, bali.parameters({
                $type: '/bali/notary/Certificate/v1',
                $tag: tag,
                $version: version,
                $permissions: '/bali/permissions/public/v1',
                $previous: bali.pattern.NONE
            }));

            // update current state
            automaton.transitionState('$generateKey');

            return certificate;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$generateKey',
                $exception: '$unexpected',
                $text: bali.text('An unexpected error occurred while attempting to generate the notary key.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This function activates a new public-private key pair by generating and caching a
     * document citation to the notarized public certificate for the key pair. It returns
     * the citation.
     *
     * @param {Catalog} certificate The notarized certificate for the new key pair.
     * @returns {Catalog} A citation to the notarized certificate.
     */
    this.activateKey = async function(certificate) {
        try {
            // load the certificate citation if necessary
            if (!citation) {
                const source = await configuration.load();
                citation = source ? bali.component(source) : undefined;
            }

            // check current state
            automaton.validateEvent('$activateKey');

            // generate a digest of the certificate
            const bytes = Buffer.from(certificate.toString(), 'utf8');
            const digest = bali.binary(await securityModule.digestBytes(bytes));

            // save the state of the certificate citation
            citation = bali.catalog({
                $protocol: PROTOCOL,
                $timestamp: timestamp,
                $tag: tag,
                $version: version,
                $digest: digest
            }, bali.parameters({
                $type: bali.component('/bali/notary/Citation/v1')
            }));
            if (debug > 2) console.log('citation: ' + citation + EOL);
            await configuration.store(citation.toString());

            // update current state
            automaton.transitionState('$activateKey');

            return citation;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$activateKey',
                $exception: '$unexpected',
                $certificate: certificate,
                $text: bali.text('An unexpected error occurred while attempting to activate the notary key.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This function replaces an existing public-private key pair with a new one. It returns
     * a new public notary certificate. Note, during key rotation the old private key is used
     * to sign the new certificate before it is destroyed.
     *
     * @returns {Catalog} The new notary certificate.
     */
    this.rotateKey = async function() {
        try {
            // load the certificate citation if necessary
            if (!citation) {
                const source = await configuration.load();
                citation = source ? bali.component(source) : undefined;
            }

            // check current state
            automaton.validateEvent('$rotateKey');

            // generate a new public-private key pair
            publicKey = bali.binary(await securityModule.rotateKeys());
            timestamp = bali.moment();  // now
            version = version.nextVersion();

            // create the new notary certificate
            const component = bali.catalog({
                $protocol: PROTOCOL,
                $timestamp: timestamp,
                $account: account,
                $publicKey: publicKey
            }, bali.parameters({
                $type: '/bali/notary/Certificate/v1',
                $tag: tag,
                $version: version,
                $permissions: '/bali/permissions/public/v1',
                $previous: citation
            }));

            // notarize the notary certificate
            const certificate = bali.catalog({
                $component: component,
                $protocol: PROTOCOL,
                $timestamp: timestamp,
                $certificate: citation
            }, bali.parameters({
                $type: bali.component('/bali/notary/Document/v1')
            }));
            var bytes = Buffer.from(certificate.toString(), 'utf8');
            const signature = bali.binary(await securityModule.signBytes(bytes));
            certificate.setValue('$signature', signature);
            if (debug > 2) console.log('certificate: ' + certificate + EOL);

            // generate a digest of the certificate
            bytes = Buffer.from(certificate.toString(), 'utf8');
            const digest = bali.binary(await securityModule.digestBytes(bytes));

            // save the state of the certificate citation
            citation = bali.catalog({
                $protocol: PROTOCOL,
                $timestamp: timestamp,
                $tag: tag,
                $version: version,
                $digest: digest
            }, bali.parameters({
                $type: bali.component('/bali/notary/Citation/v1')
            }));
            if (debug > 2) console.log('citation: ' + citation + EOL);
            await configuration.store(citation.toString());

            // update current state
            automaton.transitionState('$rotateKey');

            return certificate;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$rotateKey',
                $exception: '$unexpected',
                $text: bali.text('An unexpected error occurred while attempting to rotate the notary key.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This function causes the digital notary to forget all information
     * it knows about the current public-private key pair.
     */
    this.forgetKey = async function() {
        try {
            // check current state
            automaton.validateEvent('$forgetKey');

            // erase the state of the digital notary
            tag = undefined;
            version = undefined;
            timestamp = undefined;
            publicKey = undefined;
            citation = undefined;
            await securityModule.eraseKeys();
            await configuration.delete();

            // update current state
            automaton.transitionState('$forgetKey');

        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$forgetKey',
                $exception: '$unexpected',
                $text: bali.text('An unexpected error occurred while attempting to forget the notary key.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This function returns a citation referencing the notary certificate associated
     * with this notary key.
     *
     * @returns {Catalog} A citation referencing the notary certificate associated
     * with this notary key.
     */
    this.getCitation = async function() {
        try {
            // load the certificate citation if necessary
            if (!citation) {
                const source = await configuration.load();
                citation = source ? bali.component(source) : undefined;
            }

            // check current state
            automaton.validateEvent('$getCitation');

            // update current state
            automaton.transitionState('$getCitation');

            return citation;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$getCitation',
                $exception: '$unexpected',
                $text: bali.text('An unexpected error occurred while attempting to retrieve the certificate citation.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This function generates a document citation for the specified notarized document.
     *
     * @param {Catalog} document The document to be cited.
     * @returns {Catalog} A document citation for the notarized document.
     */
    this.citeDocument = async function(document) {
        try {
            // check current state
            automaton.validateEvent('$citeDocument');

            // validate the parameter
            validateArgument('$citeDocument', 'document', document);

            // extract the required attributes
            const parameters = document.getValue('$component').getParameters();
            const tag = parameters.getValue('$tag');
            const version = parameters.getValue('$version');
            const bytes = Buffer.from(document.toString(), 'utf8');

            // generate a digest of the document
            const digest = bali.binary(await securityModule.digestBytes(bytes));

            // create the citation
            const citation = bali.catalog({
                $protocol: PROTOCOL,
                $timestamp: bali.moment(),  // now
                $tag: tag,
                $version: version,
                $digest: digest
            }, bali.parameters({
                $type: '/bali/notary/Citation/v1'
            }));

            // update current state
            automaton.transitionState('$citeDocument');

            return citation;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$citeDocument',
                $exception: '$unexpected',
                $document: document,
                $text: bali.text('An unexpected error occurred while attempting to cite a notarized document.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };
   

    /**
     * This function determines whether or not the specified document citation matches
     * the specified notarized document. The citation only matches if its digest matches
     * the digest of the notarized document exactly.
     *
     * @param {Catalog} citation A document citation allegedly referring to the
     * specified notarized document.
     * @param {Catalog} document The notarized document to be tested.
     * @returns {Boolean} Whether or not the citation matches the specified notarized document.
     */
    this.citationMatches = async function(citation, document) {
        try {
            // check current state
            automaton.validateEvent('$citationMatches');

            validateArgument('$citationMatches', 'citation', citation);
            validateArgument('$citationMatches', 'document', document);
            const requiredProtocol = citation.getValue('$protocol').toString();
            var requiredModule;
            if (requiredProtocol === PROTOCOL) {
                requiredModule = securityModule;  // use the current one
            } else {
                requiredModule = protocols[requiredProtocol];
                if (!requiredModule) {
                    const exception = bali.exception({
                        $module: '/bali/notary/DigitalNotary',
                        $procedure: '$citationMatches',
                        $exception: '$unsupportedProtocol',
                        $expected: Object.keys(protocols),
                        $actual: requiredProtocol,
                        $text: bali.text('Attempted to use an unsupported version of the notary protocol.')
                    });
                    throw exception;
                }
            }
            const bytes = Buffer.from(document.toString(), 'utf8');
            var digest = bali.binary(await requiredModule.digestBytes(bytes));

            const result = digest.isEqualTo(citation.getValue('$digest'));

            // update current state
            automaton.transitionState('$citationMatches');

            return result;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$citationMatches',
                $exception: '$unexpected',
                $citation: citation,
                $document: document,
                $text: bali.text('An unexpected error occurred while attempting to match a citation to a notarized document.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };
   
    /**
     * This function digitally notarizes the specified component using the private notary
     * key maintained by the security module. The component must be parameterized
     * with the following parameters:
     * <pre>
     *  * $tag - a unique identifier for the document
     *  * $version - the version of the document
     *  * $permissions - the name of a notarized document containing the permissions defining
     *                   who can access the document
     *  * $previous - a citation to the previous version of the document (or bali.pattern.NONE)
     * </pre>
     * 
     * The newly notarized document is returned.
     *
     * @param {Component} component The component to be notarized.
     * @returns {Catalog} A newly notarized document containing the component.
     */
    this.notarizeDocument = async function(component) {
        try {
            // load the certificate citation if necessary
            if (!citation) {
                const source = await configuration.load();
                citation = source ? bali.component(source) : undefined;
            }

            // check current state
            automaton.validateEvent('$notarizeDocument');

            // validate the component parameter
            validateArgument('$notarizeDocument', 'component', component);

            // create the document
            const notarizedComponent = bali.catalog({
                $component: component,
                $protocol: PROTOCOL,
                $timestamp: bali.moment(),  // now
                $certificate: citation || bali.pattern.NONE  // self-signed certificate
            }, bali.parameters({
                $type: bali.component('/bali/notary/Document/v1')
            }));

            // notarize the document
            const bytes = Buffer.from(notarizedComponent.toString(), 'utf8');
            const signature = bali.binary(await securityModule.signBytes(bytes));
            notarizedComponent.setValue('$signature', signature);

            // update current state
            automaton.transitionState('$notarizeDocument');

            return notarizedComponent;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$notarizeDocument',
                $exception: '$unexpected',
                $component: component,
                $text: bali.text('An unexpected error occurred while attempting to notarize a document.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This function determines whether or not the notary seal on the specified notarized
     * document is valid.
     *
     * @param {Catalog} document The notarized document to be tested.
     * @param {Catalog} certificate A document containing the public certificate for the
     * private notary key that allegedly notarized the specified notarized document.
     * @returns {Boolean} Whether or not the notary seal on the notarized document is valid.
     */
    this.documentValid = async function(document, certificate) {
        try {
            // load the certificate citation if necessary
            if (!citation) {
                const source = await configuration.load();
                citation = source ? bali.component(source) : undefined;
            }

            // validate the parameters
            validateArgument('$documentIsValid', 'document', document);
            validateArgument('$documentIsValid', 'certificate', certificate);

            // separate the signature from the document
            const catalog = bali.catalog.extraction(document, bali.list([
                '$component',
                '$protocol',
                '$timestamp',
                '$certificate'
            ]));
            const signature = document.getValue('$signature');

            // extract the public key from the certificate
            const publicKey = certificate.getValue('$publicKey');

            // find a security module that is compatible with the protocol
            var requiredModule;
            const requiredProtocol = certificate.getValue('$protocol').toString();
            if (requiredProtocol === PROTOCOL) {
                requiredModule = securityModule;  // use the current one
            } else {
                requiredModule = protocols[requiredProtocol];
                if (!requiredModule) {
                    const exception = bali.exception({
                        $module: '/bali/notary/DigitalNotary',
                        $procedure: '$documentIsValid',
                        $exception: '$unsupportedProtocol',
                        $expected: Object.keys(protocols),
                        $actual: requiredProtocol,
                        $text: bali.text('Attempted to use an unsupported version of the notary protocol.')
                    });
                    throw exception;
                }
            }

            // validate the signature against the document
            const bytes = Buffer.from(catalog.toString(), 'utf8');
            const result = await requiredModule.validSignature(publicKey.getValue(), signature.getValue(), bytes);

            // update current state
            automaton.transitionState('$documentValid');

            return result;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$documentIsValid',
                $exception: '$unexpected',
                $document: document,
                $certificate: certificate,
                $text: bali.text('An unexpected error occurred while attempting to validate a notarized document.')
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    return this;
};
DigitalNotary.prototype.constructor = DigitalNotary;
exports.DigitalNotary = DigitalNotary;


// PRIVATE FUNCTIONS

/**
 * This function validates the specified parameter type and value for a parameter that was
 * passed into the specified function. If either the type or value is not valid an exception
 * is thrown. This function is called recursively for any parameters that contain attributes.
 * 
 * @param {String} functionName The name of the function to which the parameter was passed. 
 * @param {String} parameterName The name of the parameter that was passed. 
 * @param {Object} parameterValue The value of the parameter that was passed. 
 * @param {String} parameterType The expected type of the parameter that was passed. 
 */
const validateArgument = function(functionName, parameterName, parameterValue, parameterType) {
    parameterType = parameterType || parameterName;
    if (parameterValue) {
        switch (parameterType) {
            case 'binary':
                if (parameterValue.isComponent && parameterValue.isType('$Binary')) return;
                break;
            case 'moment':
                if (parameterValue.isComponent && parameterValue.isType('$Moment')) return;
                break;
            case 'name':
                if (parameterValue.isComponent && parameterValue.isType('$Name')) return;
                break;
            case 'tag':
                if (parameterValue.isComponent && parameterValue.isType('$Tag')) return;
                break;
            case 'version':
                if (parameterValue.isComponent && parameterValue.isType('$Version')) return;
                break;
            case 'directory':
                // A directory must be a string that matches a specific pattern
                const pattern = new RegExp('/?(\\w+/)+');
                if (typeof parameterValue === 'string' && pattern.test(parameterValue)) return;
                break;
            case 'component':
                if (parameterValue.isComponent) return;
                break;
            case 'citation':
                // A citation must have the following:
                //  * a parameterized type of /bali/notary/Citation/v...
                //  * exactly five specific attributes
                if (parameterValue.isComponent && parameterValue.isEqualTo(bali.pattern.NONE)) return;
                if (parameterValue.isComponent && parameterValue.isType('$Catalog') && parameterValue.getSize() === 5) {
                    validateArgument(functionName, parameterName + '.protocol', parameterValue.getValue('$protocol'), 'version');
                    validateArgument(functionName, parameterName + '.timestamp', parameterValue.getValue('$timestamp'), 'moment');
                    validateArgument(functionName, parameterName + '.tag', parameterValue.getValue('$tag'), 'tag');
                    validateArgument(functionName, parameterName + '.version', parameterValue.getValue('$version'), 'version');
                    validateArgument(functionName, parameterName + '.digest', parameterValue.getValue('$digest'), 'binary');
                    const parameters = parameterValue.getParameters();
                    if (parameters && parameters.getKeys().getSize() === 1) {
                        validateArgument(functionName, parameterName + '.parameters.type', parameters.getValue('$type'), 'name');
                        if (parameters.getValue('$type').toString().startsWith('/bali/notary/Citation/v')) return;
                    }
                }
                break;
            case 'certificate':
                // A certificate must have the following:
                //  * a parameterized type of /bali/notary/Certificate/v...
                //  * exactly four specific attributes
                //  * and be parameterized with exactly 5 specific parameters
                if (parameterValue.isComponent && parameterValue.isType('$Catalog') && parameterValue.getSize() === 4) {
                    validateArgument(functionName, parameterName + '.protocol', parameterValue.getValue('$protocol'), 'version');
                    validateArgument(functionName, parameterName + '.timestamp', parameterValue.getValue('$timestamp'), 'moment');
                    validateArgument(functionName, parameterName + '.account', parameterValue.getValue('$account'), 'tag');
                    validateArgument(functionName, parameterName + '.publicKey', parameterValue.getValue('$publicKey'), 'binary');
                    const parameters = parameterValue.getParameters();
                    if (parameters && parameters.getKeys().getSize() === 5) {
                        validateArgument(functionName, parameterName + '.parameters.type', parameters.getValue('$type'), 'name');
                        validateArgument(functionName, parameterName + '.parameters.tag', parameters.getValue('$tag'), 'tag');
                        validateArgument(functionName, parameterName + '.parameters.version', parameters.getValue('$version'), 'version');
                        validateArgument(functionName, parameterName + '.parameters.permissions', parameters.getValue('$permissions'), 'name');
                        validateArgument(functionName, parameterName + '.parameters.previous', parameters.getValue('$previous'), 'citation');
                        if (parameters.getValue('$type').toString().startsWith('/bali/notary/Certificate/v') &&
                            parameters.getValue('$permissions').toString().startsWith('/bali/permissions/public/v')) return;
                    }
                }
                break;
            case 'document':
                // A document must have the following:
                //  * a parameterized type of /bali/notary/Document/v...
                //  * exactly five specific attributes including a $component attribute
                //  * the $component attribute must be parameterized with at least four parameters
                //  * the $component attribute may have a parameterized type as well
                if (parameterValue.isComponent && parameterValue.isType('$Catalog') && parameterValue.getSize() === 5) {
                    validateArgument(functionName, parameterName + '.component', parameterValue.getValue('$component'), 'component');
                    validateArgument(functionName, parameterName + '.protocol', parameterValue.getValue('$protocol'), 'version');
                    validateArgument(functionName, parameterName + '.timestamp', parameterValue.getValue('$timestamp'), 'moment');
                    validateArgument(functionName, parameterName + '.certificate', parameterValue.getValue('$certificate'), 'citation');
                    validateArgument(functionName, parameterName + '.signature', parameterValue.getValue('$signature'), 'binary');
                    var parameters = parameterValue.getValue('$component').getParameters();
                    if (parameters) {
                        if (parameters.getValue('$type')) validateArgument(functionName, parameterName + '.parameters.type', parameters.getValue('$type'), 'name');
                        validateArgument(functionName, parameterName + '.parameters.tag', parameters.getValue('$tag'), 'tag');
                        validateArgument(functionName, parameterName + '.parameters.version', parameters.getValue('$version'), 'version');
                        validateArgument(functionName, parameterName + '.parameters.permissions', parameters.getValue('$permissions'), 'name');
                        validateArgument(functionName, parameterName + '.parameters.previous', parameters.getValue('$previous'), 'citation');
                        parameters = parameterValue.getParameters();
                        if (parameters && parameters.getKeys().getSize() === 1) {
                            if (parameters.getValue('$type').toString().startsWith('/bali/notary/Document/v')) return;
                        }
                    }
                }
                break;
        }
    }
    const exception = bali.exception({
        $module: '/bali/notary/DigitalNotary',
        $procedure: functionName,
        $exception: '$invalidParameter',
        $parameter: bali.text(parameterName),
        $value: parameterValue ? bali.text(parameterValue.toString()) : bali.pattern.NONE,
        $text: bali.text('An invalid parameter value was passed to the function.')
    });
    throw exception;
};
DigitalNotary.prototype.constructor = DigitalNotary;
exports.DigitalNotary = DigitalNotary;