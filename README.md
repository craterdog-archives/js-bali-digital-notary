![Logo](https://raw.githubusercontent.com/craterdog-bali/bali-project-documentation/master/images/CraterDogLogo.png)

### Bali Digital Notary
This project provides a JavaScript version of the digital notary classes for the [_Bali Cloud Environment™_](https://github.com/craterdog-bali/bali-project-documentation/wiki). It defines a format for digitally notarized documents and a digital notary proxy to a hardware security module (HSM) that handles all private key operations including generating public-private key pairs. It is designed to work with documents that were exported from components created using the [_Bali Component Framework™_](https://github.com/craterdog-bali/js-bali-component-framework) but will work with most string based documents.

![Pyramid](https://raw.githubusercontent.com/craterdog-bali/bali-project-documentation/master/images/Bali%20Pyramid%20-%20Digital%20Notary.png)

_**WARNING**_
_This project is still in its early stages and the classes and interfaces to the classes are likely to change. Nevertheless, the project in its current state should work well as a digital notarization package._

### Quick Links
For more information on this project click on the following links:
 * [wiki](https://github.com/craterdog-bali/js-bali-digital-notary/wiki)
 * [node package](https://www.npmjs.com/package/bali-digital-notary)
 * [release notes](https://github.com/craterdog-bali/js-bali-digital-notary/wiki/releases)
 * [project documentation](https://github.com/craterdog-bali/bali-project-documentation/wiki)

### Highlighted Components
 * **DigitalNotary** - a singleton object that acts as a proxy to the hardware security module.
 * **NotarizeDocument** - a class that defines the structure of a notarized document.

![Notarized Document](https://raw.githubusercontent.com/craterdog-bali/bali-project-documentation/master/images/Notarized%20Document.png)

### Getting Started
To install this NodeJS package:
```
npm install bali-digital-notary
```

### Contributing
Project contributors are always welcome. Create a [fork](https://github.com/craterdog-bali/js-bali-digital-notary) of the project and add cool new functionality. When you are ready to contribute the changes create a subsequent ["pull request"](https://help.github.com/articles/about-pull-requests/). Any questions and comments can be sent to craterdog@gmail.com.
