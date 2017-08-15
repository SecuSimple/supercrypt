# supercrypt
A lightweight JavaScript library for symmetric encryption

## Key features
- optimized for binary / file encryption
- uses crypto standard AES on 128b
- includes HMAC authentication (EtA - Encrypt then Authenticate) for guaranteed message authenticity
- written in ES5, ensuring high browser compatibility
- works with node.js and client-side module loaders

## Installation
Node.js:
```
npm install supercrypt
```

Client / Browser:
```
bower install supercrypt
```

## Usage
Modular include (using Node.js):
```javascript
var supercrypt = require('supercrypt');
```

Client / Browser include (using require.js):
```javascript
require.config({
    packages: [
        {
            name: 'supercrypt',
            location: 'path-to/bower_components/supercrypt',
            main: 'index'
        }
    ]
});

require(['supercrypt'], function (supercrypt) {
    //your code here
});
```

Using the library:
```javascript
encryptor = new supercrypt({
    fileSize: 100, //bytes
    saveBlock: function(data, callback) {},
    readBlock: function(size, callback) {},
    progressHandler: function(progressPercentage) {},
    finishHandler: function() {}, //called on success
    errorHandler: function(errCode) {}, //called on error
});

var seedList = [1,2,3,4,5,6,7,8,9,0]; //random array of numbers
encryptor.encrypt('key', seedList);
```