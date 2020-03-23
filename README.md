## The Bali Digital Notary™ (v2)
<img src="https://craterdog.com/images/CraterDogLogo.png" width="50%">

### Quick Links
For more information on this project click on the following links:
 * [project documentation](https://github.com/craterdog-bali/js-bali-digital-notary/wiki)
 * [node packages](https://www.npmjs.com/package/bali-digital-notary)
 * [release notes](https://github.com/craterdog-bali/js-bali-digital-notary/wiki/release-notes)
 * [code examples](https://github.com/craterdog-bali/js-bali-digital-notary/wiki/code-examples)

### Getting Started
To install this NodeJS package, execute the following command:
```
npm install bali-digital-notary
```
Then add the following line to your NodeJS modules:
```
const debug = 1;  // debugging level: [0..3]
const securityModule = require('bali-digital-notary').ssm(directory, debug);
const notary = require('bali-digital-notary').notary(securityModule, account, directory, debug);
```

### Contributing
Project contributors are always welcome. Create a
[fork](https://github.com/craterdog-bali/js-bali-digital-notary) of the project and add cool
new things to the project. When you are ready to contribute the changes create a subsequent
["pull request"](https://help.github.com/articles/about-pull-requests/). Any questions and
comments can be sent to [craterdog@gmail.com](mailto:craterdog@gmail.com).
