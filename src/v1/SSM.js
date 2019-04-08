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

///////////////////////////////////////////////////////////////////////////////////////
// This module should be used for LOCAL TESTING ONLY.  It is NOT SECURE and provides //
// no guarantees on protecting access to the private key.  YOU HAVE BEEN WARNED!!!   //
///////////////////////////////////////////////////////////////////////////////////////


/*
 * This module uses the singleton pattern to provide an object that simulates a hardware
 * security module (HSM) for all cryptographic operations involving the private key. It
 * implements these operations as a software security module to allow testing without an
 * actual HSM.
 */
const pfs = require('fs').promises;
const os = require('os');
const crypto = require('crypto');
const ec_pem = require('ec-pem');
const bali = require('bali-component-framework');


// PUBLIC APIs

/**
 * This function returns an object that implements the public certificate API for the 
 * software security module (SSM).
 *
 * @returns {Object} A proxy to the public software security module.
 */
exports.publicAPI = function() {

    return {

        /**
         * This function returns a string providing attributes about this software security module.
         *
         * @returns {String} A string providing attributes about this software security module.
         */
        toString: function() {
            const catalog = bali.catalog({
                $module: '$v1SSM',
                $protocol: bali.parse(PROTOCOL),
                $curve: bali.text(CURVE),
                $digest: bali.text(DIGEST),
                $signature: bali.text(SIGNATURE),
                $cipher: bali.text(CIPHER)
            });
            return catalog.toString();
        },

        /**
         * This function generates a document citation for the specified document.
         *
         * @param {Catalog} document The document to be cited.
         * @returns {Catalog} A document citation for the document.
         */
        citeDocument: function(document) {
            // validate the parameters
            if (!document || !document.getTypeId || document.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$citeDocument',
                    $exception: '$invalidParameter',
                    $parameter: document ? bali.text(document.toString()) : bali.NONE,
                    $text: bali.text('The document to be cited is invalid.')
                });
                throw exception;
            }
            // TODO: check for undefined $document
            const parameters = document.getValue('$document').getParameters();
            if (!parameters || !parameters.getParameter('$tag') || !parameters.getParameter('$version')) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$citeDocument',
                    $exception: '$missingParameters',
                    $document: document,
                    $text: bali.text('The document identity parameters are missing.')
                });
                throw exception;
            }

            // generate the document citation
            try {
                // TODO: check tag and version component type?
                const tag = parameters.getParameter('$tag');
                const version = parameters.getParameter('$version');
                const digest = generateDigest(document);
                const citation = bali.catalog({
                    $protocol: bali.parse(PROTOCOL),  // parses the version number of the protocol
                    $timestamp: bali.moment(),  // now
                    $tag: tag,
                    $version: version,
                    $digest: digest
                }, bali.parameters({
                    $type: '$Citation'
                }));
                return citation;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$citeDocument',
                    $exception: '$unexpected',
                    $document: document,
                    $text: bali.text('An unexpected error occurred while attempting to cite a document.')
                }, cause);
                throw exception;
            }
        },

        /**
         * This function determines whether or not the specified document citation matches
         * the specified document. The citation only matches if its digest matches the
         * digest of the document exactly.
         *
         * @param {Catalog} citation A document citation allegedly referring to the
         * specified document.
         * @param {Catalog} document The document to be tested.
         * @returns {Boolean} Whether or not the citation matches the specified document.
         */
        citationMatches: function(citation, document) {
            // validate the parameters
            if (!citation || !citation.getTypeId || citation.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$citationMatches',
                    $exception: '$invalidParameter',
                    $parameter: citation ? bali.text(citation.toString()) : bali.NONE,
                    $text: bali.text('The document citation is invalid.')
                });
                throw exception;
            }
            if (!document || !document.getTypeId || document.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$citationMatches',
                    $exception: '$invalidParameter',
                    $parameter: document ? bali.text(document.toString()) : bali.NONE,
                    $text: bali.text('The document is invalid.')
                });
                throw exception;
            }

            // check the citation
            try {
                var digest = generateDigest(document);
                return digest.isEqualTo(citation.getValue('$digest'));
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$citationMatches',
                    $exception: '$unexpected',
                    $document: document,
                    $citation: citation,
                    $text: bali.text('An unexpected error occurred while attempting to verify a document citation.')
                }, cause);
                throw exception;
            }
        },

        /**
         * This function determines whether or not the notary seal on the specified document
         * is valid.
         *
         * @param {Catalog} document The notarized document to be tested.
         * @param {Catalog} certificate A catalog containing the public certificate for the
         * private notary key that allegedly notarized the specified document.
         * @returns {Boolean} Whether or not the notary seal on the document is valid.
         */
        documentIsValid: function(document, certificate) {
            // validate the parameters
            if (!document || !document.getTypeId || document.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$documentIsValid',
                    $exception: '$invalidParameter',
                    $parameter: document ? bali.text(document.toString()) : bali.NONE,
                    $text: bali.text('The document format is invalid.')
                });
                throw exception;
            }
            if (!certificate || !certificate.getTypeId || certificate.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$documentIsValid',
                    $exception: '$invalidParameter',
                    $parameter: certificate ? bali.text(certificate.toString()) : bali.NONE,
                    $text: bali.text('The certificate format is invalid.')
                });
                throw exception;
            }

            try {
                const catalog = bali.catalog.extraction(document, bali.list([
                    '$document',
                    '$protocol',
                    '$timestamp',
                    '$certificate'
                ]));  // everything but the signature
                const publicKey = certificate.getValue('$publicKey');
                const signature = document.getValue('$signature');
                return signatureIsValid(catalog, publicKey, signature);
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$documentIsValid',
                    $exception: '$unexpected',
                    $document: document,
                    $certificate: certificate,
                    $text: bali.text('An unexpected error occurred while attempting to verify a notarized document.')
                }, cause);
                throw exception;
            }
        },

        /**
         * This function uses the specified public notary certificate to encrypt the specified
         * document in such a way that only the intended recipient of the encrypted document can
         * decrypt it using their private notary key. The result is an authenticated encrypted
         * message (AEM) containing the ciphertext and other required attributes needed to
         * decrypt the message.
         *
         * @param {Component} document The document to be encrypted using the specified
         * public notary certificate.
         * @param {Catalog} certificate A catalog containing the public certificate for the
         * intended recipient of the encrypted document.
         * @returns {Catalog} An authenticated encrypted message (AEM) containing the ciphertext
         * and other required attributes for the encrypted document.
         */
        encryptDocument: function(document, certificate) {
            // validate the parameters
            if (!document || !document.getTypeId) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$encryptDocument',
                    $exception: '$invalidParameter',
                    $parameter: document ? bali.text(document.toString()) : bali.NONE,
                    $text: bali.text('The document format is invalid.')
                });
                throw exception;
            }
            if (!certificate || !certificate.getTypeId || certificate.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$encryptDocument',
                    $exception: '$invalidParameter',
                    $parameter: certificate ? bali.text(certificate.toString()) : bali.NONE,
                    $text: bali.text('The certificate format is invalid.')
                });
                throw exception;
            }

            try {
                const publicKey = certificate.getValue('$publicKey');
                const aem = encryptMessage(document, publicKey);
                return aem;
            } catch (cause) {
                // create a digest of the document to maintain privacy
                var digest;
                if (document) {
                    const digest = generateDigest(document);
                }
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$encryptDocument',
                    $exception: '$unexpected',
                    $digest: digest || bali.NONE,
                    $publicKey: publicKey || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to encrypt a document.')
                }, cause);
                throw exception;
            }
        }
    };
};

/**
 * This function returns an object that implements the private key API for the software
 * security module (SSM). The internal attributes for the notary key are hidden from
 * the code that is using the notary key, but it is NOT fool-proof. It should only be
 * used for testing purposes.
 *
 * @param {Tag} account The unique tag for the account that owns the notary key.
 * @param {String} testDirectory An optional directory to use for local testing.
 * @returns {Object} A proxy to the test software security module managing the private key.
 */
exports.privateAPI = function(account, testDirectory) {
    var notaryTag;            // the unique tag for the notary key
    var version;              // the current version of the notary key
    var timestamp;            // the timestamp of when the key was generated
    var publicKey;            // the public key residing in the certificate in the cloud
    var privateKey;           // the local private key that is used for signing and decryption
    var notaryCertificate;    // the public notary certificate containing the public key
    var certificateCitation;  // a document citation for the public notary certificate
    var configDirectory;      // the path to the configuration directory
    var keyFilename;          // the name of the configuration file containing the keys
    var certificateFilename;  // the name of the configuration file containing the certificate

    return {

        /**
         * This function returns a string providing attributes about this software security module.
         *
         * @returns {String} A string providing attributes about this software security module.
         */
        toString: function() {
            const catalog = bali.catalog({
                $module: '$v1SSM',
                $protocol: bali.parse(PROTOCOL),
                $curve: bali.text(CURVE),
                $digest: bali.text(DIGEST),
                $signature: bali.text(SIGNATURE),
                $cipher: bali.text(CIPHER),
                $account: account,
                $certificate: certificateCitation
            }, bali.parameters({
                $tag: notaryTag,
                $version: version
            }));
            return catalog.toString();
        },

        /**
         * This function initializes the API.
         */
        initializeAPI: async function() {
            try {
                // create the configuration directory structure if necessary
                configDirectory = await createDirectory(testDirectory, account);
                keyFilename = configDirectory + 'NotaryKey.bali';
                certificateFilename = configDirectory + 'NotaryCertificate.bali';

                // read in the notary key attributes (if possible)
                try {
                    if (await doesExist(keyFilename)) {
                        // read in the notary key information
                        const keys = await loadKeys(keyFilename);
                        timestamp = keys.getValue('$timestamp');
                        publicKey = keys.getValue('$publicKey');
                        privateKey = keys.getValue('$privateKey');
                        certificateCitation = keys.getValue('$certificate');
                        notaryTag = certificateCitation.getValue('$tag');
                        version = certificateCitation.getValue('$version');
                    }
                    if (await doesExist(certificateFilename)) {
                        // read in the notary certificate information
                        notaryCertificate = await loadCertificate(certificateFilename);
                    }
                } catch (cause) {
                    const exception = bali.exception({
                        $module: '$v1SSM',
                        $function: '$initializeAPI',
                        $exception: '$directoryAccess',
                        $account: account || bali.NONE,
                        $directory: configDirectory ? bali.text(configDirectory) : bali.NONE,
                        $text: bali.text('The configuration directory could not be accessed.')
                    }, cause);
                    throw exception;
                }
                this.initializeAPI = undefined;  // can only be called once
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$initializeAPI',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $directory: configDirectory ? bali.text(configDirectory) : bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to initialize the API.')
                }, cause);
                throw exception;
            }
        },

        /**
         * This function returns the notary certificate associated with this notary key.
         *
         * @returns {Catalog} The notary certificate associated with this notary key.
         */
        getCertificate: async function() {
            if (this.initializeAPI) await this.initializeAPI();
            return notaryCertificate;
        },

        /**
         * This function returns a citation referencing the notary certificate associated
         * with this notary key.
         *
         * @returns {Catalog} A citation referencing the notary certificate associated
         * with this notary key.
         */
        getCitation: async function() {
            if (this.initializeAPI) await this.initializeAPI();
            return certificateCitation;
        },

        /**
         * This function generates a new public-private key pair and uses the private key as the
         * new notary key. It returns the new public notary certificate. Note, during regeneration
         * the old private key is used to sign the new certificate before it is destroyed.
         *
         * @returns {Catalog} The new notary certificate.
         */
        generateKey: async function() {
            if (this.initializeAPI) await this.initializeAPI();
            try {
                const isRegeneration = !!privateKey;

                // generate a new public-private key pair
                const keys = generateKeys();
                notaryTag = notaryTag || bali.tag();  // generate a new tag if necessary
                version = version ? bali.version.nextVersion(version) : bali.version();
                timestamp = bali.moment();
                publicKey = keys.getValue('$publicKey');  // done with existing public key
                privateKey = privateKey || keys.getValue('$privateKey');  // but need existing private key

                // create the new notary certificate document
                const document = bali.catalog({
                    $protocol: bali.parse(PROTOCOL),
                    $timestamp: timestamp,
                    $account: account,
                    $publicKey: publicKey
                }, bali.parameters({
                    $type: '$Certificate',
                    $tag: notaryTag,
                    $version: version,
                    $permissions: '$Public',
                    $previous: isRegeneration ? certificateCitation : bali.NONE
                }));

                // notarize the notary certificate document
                notaryCertificate = bali.catalog({
                    $document: document,
                    $protocol: bali.parse(PROTOCOL),
                    $timestamp: bali.moment(),  // now
                    $certificate: isRegeneration ? certificateCitation : bali.NONE
                }, bali.parameters({
                    $type: '$Document'
                }));
                const signature = generateSignature(notaryCertificate, privateKey);
                notaryCertificate.setValue('$signature', signature);

                // now we can save the new key
                privateKey = keys.getValue('$privateKey');

                // cache the new certificate citation
                const digest = generateDigest(notaryCertificate);
                certificateCitation = bali.catalog({
                    $protocol: bali.parse(PROTOCOL),
                    $timestamp: bali.moment(),  // now
                    $tag: notaryTag,
                    $version: version,
                    $digest: digest
                }, bali.parameters({
                    $type: '$Citation'
                }));

                // save the state of this notary key and certificate in the local configuration
                try {
                    const notaryKey = bali.catalog({
                        $protocol: bali.parse(PROTOCOL),
                        $timestamp: timestamp,
                        $account: account,
                        $publicKey: publicKey,
                        $privateKey: privateKey,
                        $certificate: certificateCitation
                    }, bali.parameters({
                        $type: '$Key'
                    }));
                    await storeKeys(keyFilename, notaryKey);
                    await storeCertificate(certificateFilename, notaryCertificate);
                } catch (cause) {
                    const exception = bali.exception({
                        $module: '$v1SSM',
                        $function: '$generateKey',
                        $exception: '$directoryAccess',
                        $account: account || bali.NONE,
                        $text: bali.text('The configuration directory could not be accessed.')
                    }, cause);
                    throw exception;
                }

                return notaryCertificate;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$generateKey',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to (re)generate the key pair.')
                }, cause);
                throw exception;
            }
        },

        /**
         * This function causes the digital notary to forget all information
         * it knows about the current public-private key pair.
         */
        forgetKey: async function() {
            if (this.initializeAPI) await this.initializeAPI();
            try {
                version = undefined;
                publicKey = undefined;
                privateKey = undefined;
                certificateCitation = undefined;
                notaryCertificate = undefined;
                // remove the configuration files
                await deleteKeys(keyFilename);
                await deleteCertificate(certificateFilename);
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$forget',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to forget the current key pair.')
                }, cause);
                throw exception;
            }
        },

        /**
         * This function digitally notarizes the specified document using the private notary
         * key maintained inside the software security module. The document must be parameterized
         * with the following parameters:
         * <pre>
         *  * $tag - a unique identifier for the document
         *  * $version - the version of the document
         *  * $permissions - a citation to a document containing the permissions defining who can access the document
         *  * $previous - a citation to the previous version of the document (or bali.NONE)
         * </pre>
         * 
         * The newly notarized document is returned.
         *
         * @param {Component} document The document to be notarized.
         * @returns {Catalog} The newly notarized document.
         */
        notarizeDocument: async function(document) {
            if (this.initializeAPI) await this.initializeAPI();

            // validate the parameters
            if (!document || !document.getTypeId) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$notarizeDocument',
                    $exception: '$invalidParameter',
                    $account: account,
                    $parameter: document ? bali.text(document.toString()) : bali.NONE,
                    $text: bali.text('The document format is invalid.')
                });
                throw exception;
            }
            const parameters = document.getParameters();
            if (!parameters || !parameters.getParameter('$tag') || !parameters.getParameter('$version') ||
                    !parameters.getParameter('$permissions') || !parameters.getParameter('$previous')) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$notarizeDocument',
                    $exception: '$invalidParameter',
                    $account: account,
                    $parameter: document,
                    $text: bali.text('The document must be parameterized with tag, version, permissions, and previous parameters.')
                });
                throw exception;
            }


            try {
                // construct the notarized document
                const notarizedDocument = bali.catalog({
                    $document: document,
                    $protocol: PROTOCOL,
                    $timestamp: bali.moment(),  // now
                    $certificate: certificateCitation
                }, bali.parameters({
                    $type: '$Document'
                }));
                const signature = generateSignature(notarizedDocument, privateKey);
                notarizedDocument.setValue('$signature', signature);

                return notarizedDocument;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$notarizeDocument',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $document: document || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to digitally sign a document.')
                }, cause);
                throw exception;
            }
        },

        /**
         * This function uses the notary key to decrypt the specified authenticated
         * encrypted message (AEM). The result is the decrypted document.
         *
         * @param {Catalog} aem The authenticated encrypted message to be decrypted.
         * @returns {Component} The decrypted document.
         */
        decryptDocument: async function(aem) {
            if (this.initializeAPI) await this.initializeAPI();

            // validate the parameters
            if (!aem || !aem.getTypeId || aem.getTypeId() !== bali.types.CATALOG) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$decryptDocument',
                    $exception: '$invalidParameter',
                    $account: account,
                    $parameter: aem ? bali.text(aem.toString()) : bali.NONE,
                    $text: bali.text('The authenticated encrypted message is invalid.')
                });
                throw exception;
            }

            try {
                // make sure there is a private key
                if (!privateKey) {
                    const exception = bali.exception({
                        $module: '$v1SSM',
                        $function: '$decryptDocument',
                        $exception: '$missingKey',
                        $account: account,
                        $text: bali.text('A notary key has not been generated.')
                    });
                    throw exception;
                }

                // check the protocol version
                const protocol = aem.getValue('$protocol');
                if (!protocol || protocol.toString() !== PROTOCOL) {
                    const exception = bali.exception({
                        $module: '$v1SSM',
                        $function: '$decryptDocument',
                        $exception: '$unsupportedProtocol',
                        $expected:  bali.parse(PROTOCOL),
                        $actual: protocol,
                        $text: bali.text('The document was encrypted using an unsupported version of the notary protocol.')
                    });
                    throw exception;
                }
                const document = decryptMessage(aem, privateKey);
                return document;
            } catch (cause) {
                const exception = bali.exception({
                    $module: '$v1SSM',
                    $function: '$decryptDocument',
                    $exception: '$unexpected',
                    $account: account || bali.NONE,
                    $aem: aem || bali.NONE,
                    $text: bali.text('An unexpected error occurred while attempting to decrypt an authenticated encrypted message.')
                }, cause);
                throw exception;
            }
        }
    };
};


// PRIVATE CONSTANTS

// The algorithms for this version of the protocol
const PROTOCOL = 'v1';
const CURVE = 'prime256v1';  // AKA 'secp256r1'
const DIGEST = 'sha512';
const SIGNATURE = 'sha512';
const CIPHER = 'aes-256-gcm';

// This private constant sets the POSIX end of line character
const EOL = '\n';


// PRIVATE FUNCTIONS

/**
 * This function determines whether or not the specified file exists.
 * 
 * @param {String} file The file to be checked.
 * @returns {Boolean} Whether or not the specified file exists.
 */
const doesExist = async function(file) {
    try {
        await pfs.stat(file);
        return true;
    } catch (exception) {
        if (exception.code === 'ENOENT') {
            return false;
        } else {
            throw exception;
        }
    }
};


/**
 * This function creates the configuration directories for the specified account.
 * 
 * @param {String} testDirectory An optional directory path to be used as the
 * base configuration directory.
 * @param {Tag} account The unique tag for the account associated with the
 * notary key.
 * @returns {String} The full configuration directory path for this account.
 */
const createDirectory = async function(testDirectory, account) {
    var configDirectory = testDirectory || os.homedir() + '/.bali/';
    try { await pfs.mkdir(configDirectory, 0o700); } catch (ignore) {};
    configDirectory += account.getValue() + '/';
    try { await pfs.mkdir(configDirectory, 0o700); } catch (ignore) {};
    return configDirectory;
};


/**
 * This function loads the public and private key attributes from the specified file.
 * 
 * @param {String} filename The name of the file containing the key definitions.
 * @returns {Catalog} A catalog containing the public and private key attributes.
 */
const loadKeys = async function(filename) {
    const keySource = await pfs.readFile(filename, 'utf8');
    const keys = bali.parse(keySource);
    return keys;
};


/**
 * This function stores the public and private key attributes in the specified file.
 * 
 * @param {String} filename The name of the file containing the key definitions.
 * @param {Catalog} keys A catalog containing the public and private key attributes.
 */
const storeKeys = async function(filename, keys) {
    const keySource = keys.toString() + EOL;  // add POSIX compliant <EOL>
    await pfs.writeFile(filename, keySource, {encoding: 'utf8', mode: 0o600});
};


/**
 * This function deletes the public and private key attributes stored in the specified
 * file.
 * 
 * @param {String} filename The name of the file containing the key definitions.
 */
const deleteKeys = async function(filename) {
    await pfs.unlink(filename).catch(function() {});
};


/**
 * This function loads the public certificate attributes from the specified file.
 * 
 * @param {String} filename The name of the file containing the certificate attributes.
 * @returns {Catalog} A catalog containing the public certificate attributes.
 */
const loadCertificate = async function(filename) {
    const certificateSource = await pfs.readFile(filename, 'utf8');
    const certificate = bali.parse(certificateSource);
    return certificate;
};


/**
 * This function stores the public certificate attributes in the specified file.
 * 
 * @param {String} filename The name of the file containing the certificate attributes.
 * @param {Catalog} certificate A catalog containing the public certificate attributes.
 */
const storeCertificate = async function(filename, certificate) {
    const certificateSource = certificate.toString() + EOL;  // add POSIX compliant <EOL>
    await pfs.writeFile(filename, certificateSource, {encoding: 'utf8', mode: 0o600});
};


/**
 * This function deletes the public certificate attributes stored in the specified file.
 * 
 * @param {String} filename The name of the file containing the certificate attributes.
 */
const deleteCertificate = async function(filename) {
    await pfs.unlink(filename).catch(function() {});
};


/**
 * This function generates a new public-private key pair.
 * 
 * @returns {Catalog} A catalog containing the new public and private keys.
 */
const generateKeys = function() {
    const curve = crypto.createECDH(CURVE);
    curve.generateKeys();
    return bali.catalog({
        $publicKey: bali.binary(curve.getPublicKey()),
        $privateKey: bali.binary(curve.getPrivateKey())
    }, bali.parameters({
        $type: '$KeyPair'
    }));
};


/**
 * This function returns a cryptographically secure digital digest of the
 * specified message. The generated digital digest will always be the same
 * for the same message.
 *
 * @param {Component} message The component to be digested.
 * @returns {Binary} A base 32 encoded binary string for the digital digest
 * of the message.
 */
const generateDigest = function(message) {
    const hasher = crypto.createHash(DIGEST);
    hasher.update(message.toString());
    const digest = bali.binary(hasher.digest());
    return digest;
};


/**
 * This function generates a digital signature of the specified message using
 * the specified private key. The resulting digital signature can then be
 * verified using the corresponding public key.
 * 
 * @param {Component} message The message to be digitally signed.
 * @param {Binary} privateKey A base 32 encoded binary string for the private key.
 * @returns {Binary} A base 32 encoded binary string for the digital signature.
 */
const generateSignature = function(message, privateKey) {
    const curve = crypto.createECDH(CURVE);
    curve.setPrivateKey(privateKey.getValue());
    const pem = ec_pem(curve, CURVE);
    const signer = crypto.createSign(SIGNATURE);
    signer.update(message.toString());
    const signature = bali.binary(signer.sign(pem.encodePrivateKey()));
    return signature;
};


/**
 * This function uses the specified public key to determine whether or not
 * the specified digital signature was generated using the corresponding
 * private key on the specified message.
 *
 * @param {Component} message The digitally signed message.
 * @param {Binary} publicKey A base 32 encoded binary string for the public key.
 * @param {Binary} signature A base 32 encoded binary string for the digital
 * signature generated using the corresponding private key.
 * @returns {Boolean} Whether or not the digital signature is valid.
 */
const signatureIsValid = function(message, publicKey, signature) {
    const curve = crypto.createECDH(CURVE);
    curve.setPublicKey(publicKey.getValue());
    const pem = ec_pem(curve, CURVE);
    const verifier = crypto.createVerify(SIGNATURE);
    verifier.update(message.toString());
    return verifier.verify(pem.encodePublicKey(), signature.getValue());
};


/**
 * This function uses the specified public key to generate a symmetric key that
 * is then used to encrypt the specified message. The resulting authenticated
 * encrypted message (AEM) can be decrypted using the corresponding private key.
 * 
 * @param {Component} message The message to be encrypted. 
 * @param {Binary} publicKey A base 32 encoded binary string for the public key
 * to be used to generate the symmetric key.
 * @returns {Catalog} The resulting authenticated encrypted message (AEM).
 */
const encryptMessage = function(message, publicKey) {
    // generate and encrypt a 32-byte symmetric key
    const curve = crypto.createECDH(CURVE);
    curve.generateKeys();
    const seed = curve.getPublicKey();  // use the new public key as the decryption seed
    const symmetricKey = curve.computeSecret(publicKey.getValue()).slice(0, 32);  // use only first 32 bytes

    // encrypt the message using the symmetric key
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(CIPHER, symmetricKey, iv);
    var ciphertext = cipher.update(message.toString(), 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const auth = cipher.getAuthTag();

    // construct the authenticated encrypted message (AEM)
    const aem = bali.catalog({
        $protocol: bali.parse(PROTOCOL),
        $timestamp: bali.moment(),  // now
        $seed: bali.binary(seed),
        $iv: bali.binary(iv),
        $auth: bali.binary(auth),
        $ciphertext: bali.binary(ciphertext)
    }, bali.parameters({
        $type: '$AEM'
    }));

    return aem;
};


/**
 * This function uses the specified private key and the attributes from the specified
 * authenticated encrypted message (AEM) object to generate a symmetric key that
 * is then used to decrypt the encrypted message.
 * 
 * @param {Catalog} aem The authenticated encrypted message to be decrypted. 
 * @param {Binary} privateKey A base 32 encoded binary string for the private key
 * used to regenerate the symmetric key that was used to encrypt the message.
 * @returns {Component} The decrypted message.
 */
const decryptMessage = function(aem, privateKey) {
    // extract the AEM attributes
    const seed = aem.getValue('$seed').getValue();
    const iv = aem.getValue('$iv').getValue();
    const auth = aem.getValue('$auth').getValue();
    const ciphertext = aem.getValue('$ciphertext').getValue();

    // decrypt the 32-byte symmetric key
    const curve = crypto.createECDH(CURVE);
    curve.setPrivateKey(privateKey.getValue());
    const symmetricKey = curve.computeSecret(seed).slice(0, 32);  // use only first 32 bytes

    // decrypt the ciphertext using the symmetric key
    const decipher = crypto.createDecipheriv(CIPHER, symmetricKey, iv);
    decipher.setAuthTag(auth);
    var message = decipher.update(ciphertext, undefined, 'utf8');
    message += decipher.final('utf8');
    const component = bali.parse(message);

    return component;
};
