var Encryptors = require('./enc-aescbc');
var sha256 = require('./sha256');
var hcompMac256 = require('./hmac256');
var chunkSize = 160000;

/**
  * Gets the chunkSize
  */
var getChunkSize = function () {
    return chunkSize;
}

var encryptor = function (options) {
    var algorithm,
        readMac = new Uint8Array(32),
        compMac,
        sizeRead,
        service = {
            encrypt: encrypt,
            decrypt: decrypt,
            getChunkSize: getChunkSize
        },
        defaultOps = {
            algorithm: Encryptors.AESCBC
        };

    checkOptions();
    return service;

    /**
     * Initializes the encryptor
     */
    function checkOptions() {
        if (!options) {
            options = {};
        }

        extend(options, defaultOps);

        if (!options.readBlock) {
            throw "Exception. The 'readBlock' parameter was not present in the options";
        }

        if (!options.saveBlock) {
            throw "Exception. The 'saveBlock' parameter was not present in the options";
        }

        if (!options.fileSize) {
            throw "Exception. The 'fileSize' parameter was not present in the options.";
        }

        if (!options.finishHandler) {
            throw "Exception. The 'finishHandler' parameter was not present in the options";
        }

        if (!options.errorHandler) {
            throw "Exception. The 'errorHandler' parameter was not present in the options";
        }

        //adjusting to the size of the actual content (IV 16, MAC 32)
        options.decryptionFileSize = options.fileSize - 48;
    }

    /**
     * Encrypts a byte block
     * 
     * @param {Uint8Array} block - The block to encrypt
     * @returns {Array<Byte>} The encrypted block
     */
    function encrypt(key, seedList) {
        if (!key) {
            throw "Exception. The parameter 'key' was not present";
        }

        //generating key hash
        var keyHash = getKeyHash(key);

        //initializing size
        sizeRead = 0;

        //instantiating the HMAC algorithm
        compMac = new hcompMac256(keyHash.slice(0, 16));

        //generating and saving the IV
        var iv = generateIV(seedList);
        compMac.update(iv);
        options.saveBlock(iv);

        //instantiating the encryption algorithm
        algorithm = new options.algorithm(keyHash.slice(16), iv);

        //starting the encryption
        options.readBlock(chunkSize, continueEncryption);
    }

    /**
     * Saves and continues encryption
     * 
     * @param {Uint8Array} block - The input block
     */
    function continueEncryption(block) {
        if (options.progressHandler) {
            options.progressHandler(block.byteLength);
        }

        //update total size read from file
        sizeRead += block.byteLength;

        //apply padding to last block
        if (block.byteLength < chunkSize || sizeRead === options.fileSize) {
            //computing the padding
            var paddingLength = 16 - (block.byteLength % 16),
                newBlock = new Uint8Array(block.byteLength + paddingLength);

            //setting the padding
            newBlock.set(block);
            for (var i = block.byteLength; i < newBlock.byteLength; i++) {
                newBlock[i] = paddingLength;
            }
            block = newBlock;
        }

        //encrypt the block and save
        block = algorithm.encrypt(block);
        compMac.update(block);
        options.saveBlock(block);

        //check if there's more to read
        if (!options.readBlock(chunkSize, continueEncryption)) {

            //save the mac and call the finish handler
            options.saveBlock(compMac.finalize());
            options.finishHandler();
        }
    }

    /**
     * Decrypts a byte block
     * 
     * @param {Uint8Array} block - The block to decrypt
     * @returns {Array<Byte>} The decrypted block
     */
    function decrypt(key) {
        var iv;

        if (!key) {
            throw "Exception. The parameter 'key' was not present";
        }

        //generating the key hash
        var keyHash = getKeyHash(key);
        compMac = new hcompMac256(keyHash.slice(0, 16));

        //initializing size
        sizeRead = 0;

        options.readBlock(16, function (iv) {
            //update mac with iv
            compMac.update(iv);

            //instantiating the algorithm
            algorithm = new options.algorithm(keyHash.slice(16), iv);

            //starting the decryption
            options.readBlock(chunkSize, continueDecryption);
        });
    }

    /**
     * Saves and continues encryption
     * 
     * @param {Uint8Array} block - The input block
     */
    function continueDecryption(block) {
        //update progress
        if (options.progressHandler) {
            options.progressHandler(block.byteLength);
        }

        //update total size read from file
        sizeRead += block.byteLength;

        var byteDiff = sizeRead - options.decryptionFileSize;
        if (sizeRead > options.decryptionFileSize) {
            //get the read mac from the block (last bytes bigger than the file content size)
            readMac.set(block.slice(-byteDiff));
            block = block.slice(0, -byteDiff);
        }

        //update mac
        compMac.update(block);

        //decrypt the block
        block = algorithm.decrypt(block);

        //remove the last (padding) bytes
        if (sizeRead >= options.decryptionFileSize) {
            block = block.slice(0, -(block[block.byteLength - 1]));
        }
        options.saveBlock(block);

        //check if total size read has exceeded the actual file content
        if (sizeRead <= options.decryptionFileSize) {
            //read the next block and continue decryption
            options.readBlock(chunkSize, continueDecryption);
            return;
        }

        //if not all the mac is in this block, read the next block as well
        if (byteDiff < 32) {
            options.readBlock(byteDiff, function (lastBlock) {
                readMac.set(lastBlock, byteDiff);
                validateAndFinalize();
            });
        }
        else {
            validateAndFinalize();
        }
    }

    /**
     * Validates mac and finalizes decryption
     */
    function validateAndFinalize() {
        if (validateChecksum(readMac, compMac.finalize())) {
            options.finishHandler();
        }
        else {
            options.errorHandler(1);
        }
    }

    function getKeyHash(key) {
        var hash256 = new sha256();
        hash256.update(stringToByteArray(key));
        return hash256.finalize();
    }
};

/**
 * Transforms a string into a byte array
 * @param {String} str - the string to be transformed
 * @return {Array} The resulting array
 */
function stringToByteArray(str) {
    return Array.prototype.map.call(str, function (c) { return c.charCodeAt(0); });
};

/**
 * Generate new random 128-bit key, based on seedList (a seed list)
 * If the seedlist is too short, the function will use random numbers
 * The function also uses miliseconds from current date to generate the IV
 * @param {Array<Number>} seedList - an array of seeds collected from true random sources (i.e. mouse movement)
 * @return {Array<Number>} The randomly generated Initialization Vector
 */
function generateIV(seedList) {
    var ent, dat, num, result = [];

    if (!seedList) {
        seedList = [];
    }

    for (var i = 0; i < 16; i++) {
        ent = seedList.length > 1 ? seedList.splice(i, 1) : [Math.random() * 10, Math.random() * 10];
        dat = new Date();
        num = ent.length ? ent[0] * Math.random() / 10 : (Math.random() * 10 + Math.random() * 100 + Math.random() * 1000) / 100;

        result[i] = parseInt(num * dat.getMilliseconds() / 10);
        while (result[i] > 255) {
            result[i] -= 255;
        }
    }

    return result;
}

/**
 * Extends object a with properties from object b
 * 
 * @param {object} a - The object that will get modified to include all properties
 * @param {object} b - The object to take properties from
 * @returns The modified object
 */
function extend(a, b) {
    for (var key in b)
        if (b.hasOwnProperty(key))
            a[key] = b[key];
    return a;
}

/**
 * Checks if two (typed) array(s) are equal
 * @param {ArrayBuffer} read - UInt8Array
 * @param {Array} comp - Array
 */
function validateChecksum(read, comp) {
    if (read.byteLength !== comp.length) {
        return false;
    }

    var i = read.byteLength;
    while (i--) {
        if (read[i] !== comp[i]) {
            return false;
        }
    }

    return true;
}

//setting the static function
encryptor.getChunkSize = getChunkSize;

//exports
module.exports = encryptor;