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
 * This class implements a digital notary interface that is capable of performing the following
 * functions:
 * <pre>
 *   * generateKey - generate a new notary key and return the corresponding notary certificate
 *   * activateKey - activate the notary key and return a citation to the notary certificate
 *   * getCitation - retrieve the document citation for the notary certificate
 *   * generateCredentials - generate a new set of credentials that can be used for authentication.
 *   * notarizeDocument - digitally notarize a document using the notary key
 *   * validContract - check whether or not the notary seal on a contract is valid
 *   * citeDocument - create a document citation for a document
 *   * citationMatches - check whether or not a document citation matches its cited document
 *   * refreshKey - replace the existing notary key with new one
 *   * forgetKey - forget any knowledge of the notary key
 * </pre>
 * All cryptographic operations are delegated to a security module.
 */
const bali = require('bali-component-framework').api();
const SSMv2 = require('./v2/SSM').SSM;
//const SSMv3 = require('./v3/SSM').SSM;
//const SSMv4 = require('./v4/SSM').SSM;


// PRIVATE CONSTANTS

// import the supported validation only protocols (in preferred order)
const PROTOCOLS = {
//  ...
//  v4: new SSMv4(),
//  v3: new SSMv3(),
    v2: new SSMv2()
};
const PROTOCOL = Object.keys(PROTOCOLS)[0];  // the latest protocol

// define the finite state machine
const REQUESTS = [  //                        possible request types
              '$generateKey', '$activateKey', '$getCitation', '$generateCredentials', '$notarizeDocument', '$refreshKey'
];
const STATES = {
//   current                                   allowed next states
    $limited: [ '$pending',     undefined,      undefined,           undefined,           undefined,        undefined ],
    $pending: [  undefined,    '$enabled',      undefined,           undefined,          '$pending',        undefined ],
    $enabled: [  undefined,     undefined,     '$enabled',          '$enabled',          '$enabled',       '$enabled' ]
};


// PUBLIC FUNCTIONS

/**
 * This function creates a new digital notary.
 *
 * @param {Object} securityModule An object that implements the security module interface.
 * @param {Tag} account A unique account tag for the owner of the digital notary.
 * @param {String} directory An optional directory to be used for local configuration storage. If
 * no directory is specified, a directory called '.bali/' is created in the home directory.
 * @param {Boolean|Number} debug An optional number in the range 0..3 that controls
 * the level of debugging that occurs:
 * <pre>
 *   0 (or false): debugging turned off
 *   1 (or true): log exceptions to console.error
 *   2: perform argument validation and log exceptions to console.error
 *   3: perform argument validation and log exceptions to console.error and debug info to console.log
 * </pre>
 * @returns {Object} An object that implements the API for a digital notary.
 */
const DigitalNotary = function(securityModule, account, directory, debug) {
    // validate the arguments
    if (debug === null || debug === undefined) debug = 0;  // default is off
    if (debug > 1) {
        bali.Component.validateArgument('/bali/notary/DigitalNotary', '$DigitalNotary', '$securityModule', securityModule, [
            '/javascript/Object'
        ]);
        bali.Component.validateArgument('/bali/notary/DigitalNotary', '$DigitalNotary', '$account', account, [
            '/javascript/Undefined',
            '/bali/elements/Tag'
        ]);
        bali.Component.validateArgument('/bali/notary/DigitalNotary', '$DigitalNotary', '$directory', directory, [
            '/javascript/Undefined',
            '/javascript/String'
        ]);
    }

    var configurator, configuration, controller;
    if (account) {
        // create a configurator to manage the key and state configuration
        const filename = account.getValue() + '.bali';
        configurator = bali.configurator(filename, directory, debug);
    }


    // PRIVATE METHODS

    const createDocument = function(type, attributes, tag, version, permissions, previous) {
        return bali.catalog(attributes, {
            $type: type,
            $tag: tag || bali.tag(),
            $version: version || 'v1',
            $permissions: permissions || '/bali/permissions/public/v1',
            $previous: previous || 'none'
        });
    };

    const createCitation = async function(document) {
        const tag = document.getParameter('$tag');
        const version = document.getParameter('$version');
        const bytes = Buffer.from(document.toString(), 'utf8');
        const digest = await securityModule.digestBytes(bytes);
        return bali.catalog({
            $protocol: PROTOCOL,
            $tag: tag,
            $version: version,
            $digest: digest
        }, {
            $type: '/bali/notary/Citation/v1'
        });
    };

    const createCertificate = function(publicKey, tag, version, previous) {
        const type = '/bali/notary/Certificate/v1';
        const attributes = {
            $publicKey: publicKey,
            $algorithms: bali.catalog({
                $digest: 'SHA512',
                $signature: 'ED25519'
            })
        };
        const permissions = '/bali/permissions/public/v1';
        return createDocument(type, attributes, tag, version, permissions, previous);
    };

    const createContract = async function(document, certificate) {
        const contract = bali.catalog({
            $protocol: PROTOCOL,
            $timestamp: bali.moment(),  // now
            $account: account,
            $document: document,
            $certificate: certificate || bali.pattern.NONE  // 'none' for self-signed certificate
        }, {
            $type: '/bali/notary/Contract/v1'
        });
        const bytes = Buffer.from(contract.toString(), 'utf8');
        const signature = await securityModule.signBytes(bytes);
        contract.setAttribute('$signature', signature);
        return contract;
    };


    // PUBLIC METHODS

    /**
     * This method returns a string describing the attributes of the digital notary. It must
     * not be an asynchronous function since it is part of the JavaScript language.
     *
     * @returns {String} A string describing the attributes of the digital notary.
     */
    this.toString = function() {
        const catalog = bali.catalog({
            $module: '/bali/notary/DigitalNotary',
            $protocol: PROTOCOL,
            $account: account
        });
        return catalog.toString();
    };

    /**
     * This method returns a list of the protocol versions supported by this digital notary
     * API.
     *
     * @returns {List} A list of the protocol versions supported by this digital notary API.
     */
    this.getProtocols = function() {
        try {
            return bali.list(Object.keys(PROTOCOLS));
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$getProtocols',
                $exception: '$unexpected',
                $text: 'An unexpected error occurred while attempting to retrieve the supported security protocols.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method returns the unique tag for the account that is associated with this
     * digital notary.
     *
     * @returns {Tag} The unique tag for the account that is associated with this digital
     * notary.
     */
    this.getAccount = function() {
        return account;
    };

    /**
     * This method generates a citation to the specified document.
     *
     * @param {Catalog} document The document to be cited.
     * @returns {Catalog} A citation to the document.
     */
    this.citeDocument = async function(document) {
        try {
            if (debug > 1) {
                bali.Component.validateArgument('/bali/notary/DigitalNotary', '$citeDocument', '$document', document, [
                    '/bali/collections/Catalog'
                ]);
                validateStructure('$citeDocument', 'document', document, 'document');
            }
            return await createCitation(document);
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$citeDocument',
                $exception: '$unexpected',
                $document: document,
                $text: 'An unexpected error occurred while attempting to cite a document.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method determines whether or not the specified document citation matches
     * the specified document. The citation only matches if its digest matches
     * the digest of the document exactly.
     *
     * @param {Catalog} citation A document citation allegedly referring to the
     * specified document.
     * @param {Catalog} document The document to be tested.
     * @returns {Boolean} Whether or not the citation matches the specified document.
     */
    this.citationMatches = async function(citation, document) {
        try {
            if (debug > 1) {
                bali.Component.validateArgument('/bali/notary/DigitalNotary', '$citationMatches', '$citation', citation, [
                    '/bali/collections/Catalog'
                ]);
                validateStructure('$citationMatches', 'citation', citation, 'citation');
                bali.Component.validateArgument('/bali/notary/DigitalNotary', '$citationMatches', '$document', document, [
                    '/bali/collections/Catalog'
                ]);
                validateStructure('$citationMatches', 'document', document, 'document');
            }

            const requiredProtocol = citation.getAttribute('$protocol').toString();
            var requiredModule;
            if (requiredProtocol === PROTOCOL) {
                requiredModule = securityModule;  // use the current one
            } else {
                requiredModule = PROTOCOLS[requiredProtocol];
                if (!requiredModule) {
                    const exception = bali.exception({
                        $module: '/bali/notary/DigitalNotary',
                        $procedure: '$citationMatches',
                        $exception: '$unsupportedProtocol',
                        $expected: Object.keys(PROTOCOLS),
                        $actual: requiredProtocol,
                        $text: 'Attempted to use an unsupported version of the notary protocol.'
                    });
                    throw exception;
                }
            }
            const bytes = Buffer.from(document.toString(), 'utf8');
            var digest = await requiredModule.digestBytes(bytes);

            const result = bali.areEqual(digest, citation.getAttribute('$digest'));

            return result;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$citationMatches',
                $exception: '$unexpected',
                $citation: citation,
                $document: document,
                $text: 'An unexpected error occurred while attempting to match a citation to a document.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method generates a new notary key and returns the new corresponding notary certificate.
     *
     * @returns {Catalog} The new notary certificate.
     */
    this.generateKey = async function() {
        try {
            // check current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getAttribute('$state').toString(), debug);
            }
            controller.validateEvent('$generateKey');

            // generate a new public-private key pair
            const publicKey = await securityModule.generateKeys();

            // create the new notary certificate
            const certificate = createCertificate(publicKey);

            // update current state
            const state = controller.transitionState('$generateKey');
            configuration.setAttribute('$state', state);
            configuration.setAttribute('$certificate', certificate);
            await storeConfiguration(configurator, configuration, debug);

            return certificate;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$generateKey',
                $exception: '$unexpected',
                $text: 'An unexpected error occurred while attempting to generate the notary key.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method activates a new notary key by generating and returning a document citation
     * for the specified notary certificate associated with the notary key. This function is
     * needed since a new notary certificate may or may not be self-signed depending on
     * whether it was generated locally by the end user or on their behalf in the Bali Nebula™.
     * The notary certificate in either case must be signed using the notary key that is local
     * to the user.
     *
     * @param {Catalog} contract The notarized certificate for the new notary key.
     * @returns {Catalog} A document citation for the notarized certificate.
     */
    this.activateKey = async function(contract) {
        try {
            // validate the argument
            if (debug > 1) {
                bali.Component.validateArgument('/bali/notary/DigitalNotary', '$activateKey', '$contract', contract, [
                    '/bali/collections/Catalog'
                ]);
                validateStructure('$activateKey', 'contract', contract, 'contract');
                validateStructure('$activateKey', 'contract', contract.getAttribute('$document'), 'certificate');
            }
            if (debug > 2) console.log('contract: ' + bali.document(contract));

            // check current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getAttribute('$state').toString(), debug);
            }
            controller.validateEvent('$activateKey');

            // make sure its the same certificate
            const certificate = contract.getAttribute('$document');
            if (!bali.areEqual(configuration.getAttribute('$certificate'), certificate)) {
                const exception = bali.exception({
                    $module: '/bali/notary/DigitalNotary',
                    $procedure: '$activateKey',
                    $exception: '$invalidCertificate',
                    $certificate: certificate,
                    $text: 'The certificate does not match the original certificate.'
                });
                if (debug > 0) console.error(exception.toString());
                throw exception;
            }

            // create the citation
            const citation = await createCitation(certificate);
            if (debug > 2) console.log('citation: ' + bali.document(citation));

            // update current state
            const state = controller.transitionState('$activateKey');
            configuration.setAttribute('$state', state);
            configuration.setAttribute('$citation', citation);
            configuration.setAttribute('$certificate', certificate);
            await storeConfiguration(configurator, configuration, debug);

            return citation;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$activateKey',
                $exception: '$unexpected',
                $contract: contract,
                $text: 'An unexpected error occurred while attempting to activate the notary key.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method returns a document citation to the notary certificate associated with the
     * current notary key.
     *
     * @returns {Catalog} A document citation to the notary certificate associated with the
     * current notary key.
     */
    this.getCitation = async function() {
        try {
            // check current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getAttribute('$state').toString(), debug);
            }
            const state = controller.transitionState('$getCitation');  // NOTE: straight to transition...
            configuration.setAttribute('$state', state);
            await storeConfiguration(configurator, configuration, debug);
            return configuration.getAttribute('$citation');
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$getCitation',
                $exception: '$unexpected',
                $text: 'An unexpected error occurred while attempting to retrieve the certificate citation.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method uses the citation to the current certificate and the specified salt value to
     * generate notarized credentials that can be used to authenticate the caller with a remote
     * process or service.
     *
     * @param {Tag} salt An optional random tag that was generated by the process or service
     * requesting authentication.
     * @returns {Catalog} A contract containing the notarized credentials.
     */
    this.generateCredentials = async function(salt) {
        try {
            // validate the argument
            if (debug > 1) {
                bali.Component.validateArgument('/bali/notary/DigitalNotary', '$generateCredentials', '$salt', salt, [
                    '/javascript/Undefined',
                    '/bali/elements/Tag'
                ]);
            }

            // check current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getAttribute('$state').toString(), debug);
            }
            controller.validateEvent('$generateCredentials');

            // create the new credentials
            const type = '/bali/notary/Credentials/v1';
            const attributes = {$salt: salt || bali.tag()};
            const credentials = createDocument(type, attributes);

            // notarize the credentials
            const certificate = configuration.getAttribute('$citation');
            const contract = await createContract(credentials, certificate);
            if (debug > 2) console.log('notarized credentials: ' + bali.document(contract));

            // update current state
            const state = controller.transitionState('$generateCredentials');
            configuration.setAttribute('$state', state);
            await storeConfiguration(configurator, configuration, debug);

            return contract;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$generateCredentials',
                $exception: '$unexpected',
                $salt: salt,
                $text: 'An unexpected error occurred while attempting to generate credentials.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method digitally signs the specified document using the notary key maintained
     * by the security module. The document must be parameterized with the following parameters:
     * <pre>
     *  * $tag - a unique identifier for the document
     *  * $version - the version of the document
     *  * $permissions - the name of a notarized document containing the permissions defining
     *                   who can access the document
     *  * $previous - a citation to the previous version of the document (or bali.pattern.NONE)
     * </pre>
     *
     * A contract containing the newly notarized document is returned.
     *
     * @param {Catalog} document The document to be notarized.
     * @returns {Catalog} A contract containing the newly notarized document.
     */
    this.notarizeDocument = async function(document) {
        try {
            // validate the argument
            if (debug > 1) {
                bali.Component.validateArgument('/bali/notary/DigitalNotary', '$notarizeDocument', '$document', document, [
                    '/bali/collections/Catalog'
                ]);
                validateStructure('$notarizeDocument', 'document', document, 'document');
            }

            // check current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getAttribute('$state').toString(), debug);
            }
            controller.validateEvent('$notarizeDocument');

            // create the contract
            const certificate = configuration.getAttribute('$citation');
            const contract = await createContract(document, certificate);
            if (debug > 2) console.log('notarized document: ' + bali.document(contract));

            // update current state
            const state = controller.transitionState('$notarizeDocument');
            configuration.setAttribute('$state', state);
            await storeConfiguration(configurator, configuration, debug);

            return contract;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$notarizeDocument',
                $exception: '$unexpected',
                $document: document,
                $text: 'An unexpected error occurred while attempting to notarize a document.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method determines whether or not the digital signature on the specified contract
     * is valid.
     *
     * @param {Catalog} contract The contract to be tested.
     * @param {Catalog} certificate A contract containing the notarized certificate for the
     * notary key that allegedly notarized the specified contract.
     * @returns {Boolean} Whether or not the digital signature on the contract is valid.
     */
    this.validContract = async function(contract, certificate) {
        try {
            // validate the arguments
            if (debug > 1) {
                bali.Component.validateArgument('/bali/notary/DigitalNotary', '$validContract', '$contract', contract, [
                    '/bali/collections/Catalog'
                ]);
                validateStructure('$validContract', 'contract', contract, 'contract');
                bali.Component.validateArgument('/bali/notary/DigitalNotary', '$validContract', '$certificate', certificate, [
                    '/bali/collections/Catalog'
                ]);
                validateStructure('$validContract', 'certificate', certificate, 'contract');
                validateStructure('$validContract', 'certificate', certificate.getAttribute('$document'), 'certificate');

                // make sure account tags match
                const contractAccount = contract.getAttribute('$account');
                const certificateAccount = certificate.getAttribute('$account');
                if (!bali.areEqual(contractAccount, certificateAccount)) {
                    const exception = bali.exception({
                        $module: '/bali/notary/DigitalNotary',
                        $procedure: '$validContract',
                        $exception: '$accountMismatch',
                        $contract: contract,
                        $certificate: certificate,
                        $text: 'The account tags for the contract and certificate must match.'
                    });
                    throw exception;
                }

                // make sure protocol versions match
                const contractProtocol = contract.getAttribute('$protocol');
                const certificateProtocol = certificate.getAttribute('$protocol');
                if (!bali.areEqual(contractProtocol, certificateProtocol)) {
                    const exception = bali.exception({
                        $module: '/bali/notary/DigitalNotary',
                        $procedure: '$validContract',
                        $exception: '$protocolMismatch',
                        $contract: contract,
                        $certificate: certificate,
                        $text: 'The protocol versions for the contract and certificate must match.'
                    });
                    throw exception;
                }
            }

            // find a security module that is compatible with the protocol
            var requiredModule;
            const requiredProtocol = contract.getAttribute('$protocol').toString();
            if (requiredProtocol === PROTOCOL) {
                requiredModule = securityModule;  // use the current one
            } else {
                requiredModule = PROTOCOLS[requiredProtocol];
                if (!requiredModule) {
                    const exception = bali.exception({
                        $module: '/bali/notary/DigitalNotary',
                        $procedure: '$validContract',
                        $exception: '$unsupportedProtocol',
                        $expected: Object.keys(PROTOCOLS),
                        $actual: requiredProtocol,
                        $text: 'Attempted to use an unsupported version of the notary protocol.'
                    });
                    throw exception;
                }
            }

            // separate the signature from the contract
            const catalog = bali.catalog.extraction(contract, [
                '$protocol',
                '$timestamp',
                '$account',
                '$document',
                '$certificate'
            ]);
            const signature = contract.getAttribute('$signature');

            // extract the public key from the certificate
            const publicKey = certificate.getAttribute('$document').getAttribute('$publicKey');

            // validate the signature against the unsigned contract
            const bytes = Buffer.from(catalog.toString(), 'utf8');
            const result = await requiredModule.validSignature(publicKey, signature, bytes);

            return result;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$validContract',
                $exception: '$unexpected',
                $contract: contract,
                $certificate: certificate,
                $text: 'An unexpected error occurred while attempting to validate a contract.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method replaces an existing public-private key pair with a new one. It returns a
     * notarized certificate for the new notary key.  Note, while refreshing the key the old
     * notary key is used to sign the new certificate before it is destroyed.
     *
     * @returns {Catalog} The notarized certificate for the new notary key.
     */
    this.refreshKey = async function() {
        try {
            // check current state
            if (!configuration) {
                configuration = await loadConfiguration(configurator, debug);
                controller = bali.controller(REQUESTS, STATES, configuration.getAttribute('$state').toString(), debug);
            }
            controller.validateEvent('$refreshKey');

            // generate a new public-private key pair
            const publicKey = await securityModule.rotateKeys();
            var previous = configuration.getAttribute('$citation');
            const tag = previous.getAttribute('$tag');
            const version = bali.version.nextVersion(previous.getAttribute('$version'));

            // create the new notary certificate
            const certificate = createCertificate(publicKey, tag, version, previous);
            if (debug > 2) console.log('certificate: ' + bali.document(certificate));

            // create a citation to the certificate
            const citation = await createCitation(certificate);
            if (debug > 2) console.log('citation: ' + bali.document(citation));

            // notarize the new certificate
            const contract = await createContract(certificate, previous);
            if (debug > 2) console.log('notarized certificate: ' + bali.document(contract));

            // update current state
            const state = controller.transitionState('$refreshKey');
            configuration.setAttribute('$state', state);
            configuration.setAttribute('$certificate', certificate);
            configuration.setAttribute('$citation', citation);
            await storeConfiguration(configurator, configuration, debug);

            return contract;
        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$refreshKey',
                $exception: '$unexpected',
                $text: 'An unexpected error occurred while attempting to refresh the notary key.'
            }, cause);
            if (debug > 0) console.error(exception.toString());
            throw exception;
        }
    };

    /**
     * This method causes the digital notary to forget all information
     * it knows about the current public-private key pair.
     */
    this.forgetKey = async function() {
        try {
            // erase the state of the digital notary
            await securityModule.eraseKeys();
            await deleteConfiguration(configurator, debug);
            configuration = undefined;

        } catch (cause) {
            const exception = bali.exception({
                $module: '/bali/notary/DigitalNotary',
                $procedure: '$forgetKey',
                $exception: '$unexpected',
                $text: 'An unexpected error occurred while attempting to forget the notary key.'
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
const validateStructure = function(functionName, parameterName, parameterValue, parameterType) {
    if (parameterValue) {
        var parameters;
        switch (parameterType) {
            case 'binary':
                if (parameterValue.isComponent && parameterValue.isType('/bali/strings/Binary')) return;
                break;
            case 'moment':
                if (parameterValue.isComponent && parameterValue.isType('/bali/elements/Moment')) return;
                break;
            case 'name':
                if (parameterValue.isComponent && parameterValue.isType('/bali/strings/Name')) return;
                break;
            case 'tag':
                if (parameterValue.isComponent && parameterValue.isType('/bali/elements/Tag')) return;
                break;
            case 'version':
                if (parameterValue.isComponent && parameterValue.isType('/bali/strings/Version')) return;
                break;
            case 'catalog':
                if (parameterValue.isComponent && parameterValue.isType('/bali/collections/Catalog')) return;
                break;
            case 'citation':
                // A citation must have the following:
                //  * a parameterized type of /bali/notary/Citation/v...
                //  * exactly five specific attributes
                if (parameterValue.isComponent && bali.areEqual(parameterValue, bali.pattern.NONE)) return;
                if (parameterValue.isComponent && parameterValue.isType('/bali/collections/Catalog') && parameterValue.getSize() === 4) {
                    validateStructure(functionName, parameterName + '.protocol', parameterValue.getAttribute('$protocol'), 'version');
                    validateStructure(functionName, parameterName + '.tag', parameterValue.getAttribute('$tag'), 'tag');
                    validateStructure(functionName, parameterName + '.version', parameterValue.getAttribute('$version'), 'version');
                    validateStructure(functionName, parameterName + '.digest', parameterValue.getAttribute('$digest'), 'binary');
                    parameters = parameterValue.getParameters();
                    if (parameters && parameters.getSize() === 1) {
                        const name = parameters.getAttribute('$type');
                        validateStructure(functionName, parameterName + '.parameters.type', name, 'name');
                        if (name.toString().startsWith('/bali/notary/Citation/v')) return;
                    }
                }
                break;
            case 'document':
                // Content must be parameterized with exactly 5 specific parameters
                parameters = parameterValue.getParameters();
                if (parameters && parameters.getSize() === 5) {
                    validateStructure(functionName, parameterName + '.parameters.type', parameters.getAttribute('$type'), 'name');
                    validateStructure(functionName, parameterName + '.parameters.tag', parameters.getAttribute('$tag'), 'tag');
                    validateStructure(functionName, parameterName + '.parameters.version', parameters.getAttribute('$version'), 'version');
                    validateStructure(functionName, parameterName + '.parameters.permissions', parameters.getAttribute('$permissions'), 'name');
                    validateStructure(functionName, parameterName + '.parameters.previous', parameters.getAttribute('$previous'), 'citation');
                    return;
                }
                break;
            case 'certificate':
                // A certificate must have the following:
                //  * a parameterized type of /bali/notary/Certificate/v...
                //  * exactly two specific attributes
                //  * and be parameterized with exactly 5 specific parameters
                if (parameterValue.isComponent && parameterValue.isType('/bali/collections/Catalog') && parameterValue.getSize() === 2) {
                    validateStructure(functionName, parameterName + '.publicKey', parameterValue.getAttribute('$publicKey'), 'binary');
                    validateStructure(functionName, parameterName + '.algorithms', parameterValue.getAttribute('$algorithms'), 'catalog');
                    parameters = parameterValue.getParameters();
                    if (parameters && parameters.getSize() === 5) {
                        validateStructure(functionName, parameterName + '.parameters.type', parameters.getAttribute('$type'), 'name');
                        validateStructure(functionName, parameterName + '.parameters.tag', parameters.getAttribute('$tag'), 'tag');
                        validateStructure(functionName, parameterName + '.parameters.version', parameters.getAttribute('$version'), 'version');
                        validateStructure(functionName, parameterName + '.parameters.permissions', parameters.getAttribute('$permissions'), 'name');
                        validateStructure(functionName, parameterName + '.parameters.previous', parameters.getAttribute('$previous'), 'citation');
                        if (parameters.getAttribute('$type').toString().startsWith('/bali/notary/Certificate/v') &&
                            parameters.getAttribute('$permissions').toString().startsWith('/bali/permissions/public/v')) return;
                    }
                }
                break;
            case 'contract':
                // A contract must have the following:
                //  * a parameterized type of /bali/notary/Contract/v...
                //  * exactly five specific attributes including a $document attribute
                //  * the $document attribute must be parameterized with at least four parameters
                //  * the $document attribute may have a parameterized type as well
                if (parameterValue.isComponent && parameterValue.isType('/bali/collections/Catalog') && parameterValue.getSize() === 6) {
                    validateStructure(functionName, parameterName + '.protocol', parameterValue.getAttribute('$protocol'), 'version');
                    validateStructure(functionName, parameterName + '.timestamp', parameterValue.getAttribute('$timestamp'), 'moment');
                    validateStructure(functionName, parameterName + '.account', parameterValue.getAttribute('$account'), 'tag');
                    validateStructure(functionName, parameterName + '.document', parameterValue.getAttribute('$document'), 'document');
                    validateStructure(functionName, parameterName + '.certificate', parameterValue.getAttribute('$certificate'), 'citation');
                    validateStructure(functionName, parameterName + '.signature', parameterValue.getAttribute('$signature'), 'binary');
                    parameters = parameterValue.getAttribute('$document').getParameters();
                    if (parameters) {
                        const name = parameters.getAttribute('$type');
                        if (name) validateStructure(functionName, parameterName + '.parameters.type', name, 'name');
                        validateStructure(functionName, parameterName + '.parameters.tag', parameters.getAttribute('$tag'), 'tag');
                        validateStructure(functionName, parameterName + '.parameters.version', parameters.getAttribute('$version'), 'version');
                        validateStructure(functionName, parameterName + '.parameters.permissions', parameters.getAttribute('$permissions'), 'name');
                        validateStructure(functionName, parameterName + '.parameters.previous', parameters.getAttribute('$previous'), 'citation');
                        parameters = parameterValue.getParameters();
                        if (parameters && parameters.getSize() === 1) {
                            if (parameters.getAttribute('$type').toString().startsWith('/bali/notary/Contract/v')) return;
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
        $parameter: parameterName,
        $value: parameterValue,
        $text: 'An invalid parameter value was passed to the function.'
    });
    console.error(exception.toString());  // debug > 0 if this function was called so log it
    throw exception;
};


// PRIVATE FUNCTIONS

/**
 * This function uses a configurator to store out the specified configuration catalog to
 * the local filesystem.
 *
 * @param {Configurator} configurator A filesystem backed configurator.
 * @param {Catalog} configuration A catalog containing the current configuration to be stored.
 * @param {Boolean|Number} debug An optional number in the range 0..3 that controls
 * the level of debugging that occurs:
 */
const storeConfiguration = async function(configurator, configuration, debug) {
    try {
        if (!configurator) throw Error('The digital notary is configured for public certificate operations only.');
        await configurator.store(bali.document(configuration));
    } catch (cause) {
        const exception = bali.exception({
            $module: '/bali/notary/DigitalNotary',
            $procedure: '$storeConfiguration',
            $exception: '$storageException',
            $text: 'The attempt to store the current configuration failed.'
        }, cause);
        if (debug > 0) console.error(exception.toString());
        throw exception;
    }
};


/**
 * This function uses a configurator to load the current configuration catalog from
 * the local filesystem.
 *
 * @param {Configurator} configurator A filesystem backed configurator.
 * @param {Boolean|Number} debug An optional number in the range 0..3 that controls
 * the level of debugging that occurs:
 * @returns {Catalog} A catalog containing the current configuration.
 */
const loadConfiguration = async function(configurator, debug) {
    try {
        var configuration;
        if (!configurator) throw Error('The digital notary is configured for public certificate operations only.');
        const source = await configurator.load();
        if (source) {
            configuration = bali.component(source);
        } else {
            configuration = bali.catalog({
                $state: '$limited'
            });
            await configurator.store(bali.document(configuration));
        }
        return configuration;
    } catch (cause) {
        const exception = bali.exception({
            $module: '/bali/notary/DigitalNotary',
            $procedure: '$loadConfiguration',
            $exception: '$storageException',
            $text: 'The attempt to load the current configuration failed.'
        }, cause);
        if (debug > 0) console.error(exception.toString());
        throw exception;
    }
};


/**
 * This function uses a configurator to delete the current configuration catalog from
 * the local filesystem.
 *
 * @param {Configurator} configurator A filesystem backed configurator.
 * @param {Boolean|Number} debug An optional number in the range 0..3 that controls
 * the level of debugging that occurs:
 */
const deleteConfiguration = async function(configurator, debug) {
    try {
        if (!configurator) throw Error('The digital notary is configured for public certificate operations only.');
        await configurator.delete();
    } catch (cause) {
        const exception = bali.exception({
            $module: '/bali/notary/DigitalNotary',
            $procedure: '$deleteConfiguration',
            $exception: '$storageException',
            $text: 'The attempt to delete the current configuration failed.'
        }, cause);
        if (debug > 0) console.error(exception.toString());
        throw exception;
    }
};
