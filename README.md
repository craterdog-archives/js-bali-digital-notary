![Logo](https://raw.githubusercontent.com/craterdog-bali/bali-project-documentation/master/images/CraterDogLogo.png)

### Bali Digital Notary
This project provides a JavaScript version of the digital notary classes for the [_Bali Cloud Environment™_](https://github.com/craterdog-bali/bali-project-documentation/wiki). It defines a format for digitally notarized documents and a digital notary proxy to a hardware security module (HSM) that handles all private key operations including generating public-private key pairs. It is designed to work with documents that were exported from components created using the [_Bali Component Framework™_](https://github.com/craterdog-bali/js-bali-component-framework/wiki) but will work with most string based documents.

![Pyramid](https://raw.githubusercontent.com/craterdog-bali/bali-project-documentation/master/images/BaliPyramid-DigitalNotary.png)

_**WARNING**_
_This project is still in its early stages and the classes and interfaces to the classes are likely to change._

### Quick Links
For more information on this project click on the following links:
 * [wiki](https://github.com/craterdog-bali/js-bali-digital-notary/wiki)
 * [node package](https://www.npmjs.com/package/bali-digital-notary)
 * [release notes](https://github.com/craterdog-bali/js-bali-digital-notary/wiki/releases)
 * [project documentation](https://github.com/craterdog-bali/bali-project-documentation/wiki)

### Getting Started
To install this NodeJS package, execute the following command:
```
npm install bali-digital-notary
```
Then add the following line to your NodeJS modules:
```
var notary = require('bali-digital-notary);
```

Check out the example code [here](https://github.com/craterdog-bali/js-bali-digital-notary/wiki/examples).

