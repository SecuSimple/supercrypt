(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
var encryptor = require('./src/encryptor');

window.sEncrypt = encryptor;
},{"./src/encryptor":3}],2:[function(require,module,exports){
/**
 * Initializes a new AES CBC encryptor
 * @constructor
 * @param {Array<Byte>} key - The encryption key
 * @param {Array<Byte>} iv - The initialization vector
 */
var EncryptorAESCBC = function (key, iv) {
    var encryptor = {
        encrypt: encrypt,
        decrypt: decrypt
    },
        prevEncBlock = iv,
        prevDecBlock = iv,
        // checksum = 0,
        sBox,
        shiftRowTab,
        sBoxInv,
        shiftRowTabInv,
        xTime;

    init();
    expandKey(key);

    return encryptor;
    /**
     * Encrypts the given byte array
     * @param {Uint8Array} byteArray - The typed byte array that needs to be encrypted
     */
    function encrypt(byteArray) {
        var startIndex = 0,
            endIndex,
            idx,
            eidx,
            encBlock,
            paddingValue,
            resultArray = [];

        while (startIndex < byteArray.byteLength) {
            endIndex = startIndex + 16;

            //if last block
            if (endIndex >= byteArray.byteLength) {
                endIndex = byteArray.byteLength;
                paddingValue = 16 - (endIndex - byteArray.byteLength);
            }

            //copy block to be encrypted
            encBlock = [];
            for (eidx = 0, idx = startIndex; idx < endIndex; eidx++ , idx++) {
                encBlock[eidx] = byteArray[idx];
            }

            //pad the last bytes if needed PKCS7 (including 16 * 16 bytes)
            if (paddingValue) {
                for (i = 0; i < paddingValue; i++) {
                    encBlock[eidx++] = paddingValue;
                }
            }

            // checksum = checksum ^ cksum(encBlock);
            xor(encBlock, prevEncBlock);

            encryptBlock(encBlock, key);

            prevEncBlock = encBlock.slice(0);

            for (eidx = 0, idx = resultArray.length; eidx < 16; eidx++ , idx++) {
                resultArray[idx] = encBlock[eidx];
            }

            startIndex += 16;
        }
        return resultArray;
    }

    /**
     * Decrypts the given byte array
     * @param {Uint8Array} byteArray - The typed byte array that needs to be decrypted
     */
    function decrypt(byteArray) {
        var startIndex = 0,
            eidx,
            idx,
            endIndex,
            decBlock,
            blockBefore,
            resultArray = [];

        while (startIndex < byteArray.byteLength) {
            endIndex = startIndex + 16;
            //TODO REMOVE THIS
            // if (endIndex > byteArray.byteLength) {
            //     endIndex = byteArray.byteLength;
            // }

            decBlock = [];
            for (eidx = 0, idx = startIndex; idx < endIndex; eidx++ , idx++) {
                decBlock[eidx] = byteArray[idx];
            }

            blockBefore = decBlock.slice(0);
            decryptBlock(decBlock, key);
            xor(decBlock, prevDecBlock);
            // checksum = checksum ^ cksum(decBlock);

            prevDecBlock = blockBefore;

            for (eidx = 0, idx = resultArray.length; eidx < 16; eidx++ , idx++) {
                resultArray[idx] = decBlock[eidx];
            }

            startIndex += 16;
        }
        return resultArray;
    }

    // /**
    //  * Returns the checksum
    //  * @returns {String} - the checksum as string
    //  */
    // function getChecksum() {
    //     return checksum.toString();
    // }

    // /**
    //  * Computes simple checksum of a byte array
    //  * @param {Array<Byte>} byteArray - The byte array
    //  * @returns {Number} The checksum
    //  */
    // function cksum(byteArray) {
    //     var res = 0,
    //         len = byteArray.length;
    //     for (var i = 0; i < len; i++) {
    //         res = res * 31 + byteArray[i];
    //     }
    //     return res;
    // }

    /**
     * Applies XOR on two arrays having a fixed length of 16 bytes.
     * @param {Array<Byte>} arr1 - The first array
     * @param {Array<Byte>} arr2 - The second array
     * @returns {Array<Byte>} The result array
     */
    function xor(arr1, arr2) {
        for (var i = 0; i < 16; i++) {
            arr1[i] = arr1[i] ^ arr2[i];
        }
    }

    /**
     * Combines the state with a round of the key
     */
    function addRoundKey(state, rkey) {
        for (var i = 0; i < 16; i++)
            state[i] ^= rkey[i];
    }

    /**
     * Replaces bytes in the state with bytes from the lookup table
     */
    function subBytes(state, sbox) {
        for (var i = 0; i < 16; i++)
            state[i] = sbox[state[i]];
    }

    /**
     * Shifts the rows of the state
     */
    function shiftRows(state, shifttab) {
        var h = state.slice(0);
        for (var i = 0; i < 16; i++)
            state[i] = h[shifttab[i]];
    }

    /**
     * Mixes state columns (using a fixed polinomial function)
     */
    function mixColumns(state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0],
                s1 = state[i + 1];
            var s2 = state[i + 2],
                s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            state[i + 0] ^= h ^ xTime[s0 ^ s1];
            state[i + 1] ^= h ^ xTime[s1 ^ s2];
            state[i + 2] ^= h ^ xTime[s2 ^ s3];
            state[i + 3] ^= h ^ xTime[s3 ^ s0];
        }
    }

    /**
     * Inverted mix columns
     */
    function mixColumnsInv(state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0],
                s1 = state[i + 1];
            var s2 = state[i + 2],
                s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            var xh = xTime[h];
            var h1 = xTime[xTime[xh ^ s0 ^ s2]] ^ h;
            var h2 = xTime[xTime[xh ^ s1 ^ s3]] ^ h;
            state[i + 0] ^= h1 ^ xTime[s0 ^ s1];
            state[i + 1] ^= h2 ^ xTime[s1 ^ s2];
            state[i + 2] ^= h1 ^ xTime[s2 ^ s3];
            state[i + 3] ^= h2 ^ xTime[s3 ^ s0];
        }
    }

    /**
     * Initializes the runtime and lookup tables.
     */
    function init() {
        sBox = new Array(99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171,
            118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253,
            147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154,
            7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227,
            47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170,
            251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245,
            188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61,
            100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224,
            50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213,
            78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221,
            116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29,
            158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161,
            137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22);

        shiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);

        sBoxInv = new Array(256);
        for (var i = 0; i < 256; i++)
            sBoxInv[sBox[i]] = i;

        shiftRowTabInv = new Array(16);
        for (var j = 0; j < 16; j++)
            shiftRowTabInv[shiftRowTab[j]] = j;

        xTime = new Array(256);
        for (var k = 0; k < 128; k++) {
            xTime[k] = k << 1;
            xTime[128 + k] = (k << 1) ^ 0x1b;
        }
    }

    /**
     * Expands the cipher key according to its length
     */
    function expandKey(key) {
        var kl = key.length,
            ks, Rcon = 1;
        switch (kl) {
            case 16:
                ks = 16 * (10 + 1);
                break;
            case 24:
                ks = 16 * (12 + 1);
                break;
            case 32:
                ks = 16 * (14 + 1);
                break;
            default:
                throw "Key error: Only key lengths of 16, 24 or 32 bytes allowed!";
        }
        for (var i = kl; i < ks; i += 4) {
            var temp = key.slice(i - 4, i);
            if (i % kl === 0) {
                temp = new Array(sBox[temp[1]] ^ Rcon, sBox[temp[2]],
                    sBox[temp[3]], sBox[temp[0]]);
                if ((Rcon <<= 1) >= 256)
                    Rcon ^= 0x11b;
            } else if ((kl > 24) && (i % kl == 16))
                temp = new Array(sBox[temp[0]], sBox[temp[1]],
                    sBox[temp[2]], sBox[temp[3]]);
            for (var j = 0; j < 4; j++)
                key[i + j] = key[i + j - kl] ^ temp[j];
        }
    }

    /** 
     * Encrypt a 16-byte array block using the given key
     */
    function encryptBlock(block, key) {
        var l = key.length;
        addRoundKey(block, key.slice(0, 16));
        for (var i = 16; i < l - 16; i += 16) {
            subBytes(block, sBox);
            shiftRows(block, shiftRowTab);
            mixColumns(block);
            addRoundKey(block, key.slice(i, i + 16));
        }
        subBytes(block, sBox);
        shiftRows(block, shiftRowTab);
        addRoundKey(block, key.slice(i, l));
    }

    /** 
     * Decrypts a 16-byte array block using the given key
     */
    function decryptBlock(block, key) {
        var l = key.length;
        addRoundKey(block, key.slice(l - 16, l));
        shiftRows(block, shiftRowTabInv);
        subBytes(block, sBoxInv);
        for (var i = l - 32; i >= 16; i -= 16) {
            addRoundKey(block, key.slice(i, i + 16));
            mixColumnsInv(block);
            shiftRows(block, shiftRowTabInv);
            subBytes(block, sBoxInv);
        }
        addRoundKey(block, key.slice(0, 16));
    }


};

//exports
module.exports = {
    AESCBC: EncryptorAESCBC
};
},{}],3:[function(require,module,exports){
var Encryptors = require('./enc-aescbc');
var sha256 = require('./sha256');
var hcompMac256 = require('./hmac256');

var encryptor = function (options) {
    var algorithm,
        readMac = new Uint8Array(32),
        compMac,
        chunkSize = 160000,
        sizeRead,
        service = {
            encrypt: encrypt,
            decrypt: decrypt
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
        options.fileSize -= 48;
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
        compMac = new hcompMac256(keyHash.slice(0, 16));

        //generating and saving the IV
        var iv = generateIV(seedList);
        compMac.update(iv);
        options.saveBlock(iv);

        //instantiating the hcompMac and the encryption algorithm
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
        compMac = new hcompMac256(keyHash(0, 16));

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

        var byteDiff = sizeRead - options.fileSize;
        if (sizeRead > options.fileSize) {
            //get the read mac from the block (last bytes bigger than the file content size)
            readMac.set(block.slice(-byteDiff), 0);
            block = block.slice(0, -byteDiff);
        }

        //decrypt the block and save
        compMac.update(block);
        block = algorithm.decrypt(block);

        //remove the last (padding) bytes
        if (sizeRead >= options.fileSize) {
            block.slice(0, -(block[block.byteLength - 1]));
        }
        options.saveBlock(block);

        //check if total size read has exceeded the actual file content
        if (sizeRead <= options.fileSize) {
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
        if (arraybufferEqual(readMac.buffer, compMac.buffer)) {
            options.finishHandler();
        }
        else {
            options.errorHandler(1);
        }
    }

    function getKeyHash(key) {
        var hash256 = new sha256();
        hash256.update(key);
        return hash256.finalize();
    }
};

/**
 * Transforms a string into a fixed size byte array
 * @param {String} string - the string to be transformed
 * @param {Number} len - the desired destination length
 * @returns {Array} The resulting array padded with 0 at the end
 */
function stringToByteArray(string, len) {
    if (string.length > len) {
        throw 'String is too large';
    }

    var lengthArray = new Array(len);
    for (var i = string.length - 1, j = len - 1; i >= 0; i-- , j--) {
        lengthArray[j] = string.charCodeAt(i);
    }

    while (j >= 0) {
        lengthArray[j--] = 0;
    }
    return lengthArray;
}


/**
 * Transforms a byte array into string
 * @param {TypedArray} byteArray - the typed byte array to be transformed
 * @returns {String} The resulting string
 */
function byteArrayToString(byteArray) {
    var string = '';
    for (var i = 0; i < byteArray.byteLength; i++) {
        if (byteArray[i] === 0) {
            continue;
        }

        string += String.fromCharCode(byteArray[i]);
    }
    return string;
}

/**
 * Generate new random 128-bit key, based on seedList (a seed list)
 * If the seedlist is too short, the function will use random numbers
 * The function also uses miliseconds from current date to generate the IV
 * @param {Array<Number>} seedList - an array of seeds collected from true random sources (i.e. mouse movement)
 * @returns {Array<Number>} The randomly generated Initialization Vector
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
 * Checks if two array buffers are equal
 * @param {ArrayBuffer} buf1 - Array buffer 1
 * @param {ArrayBiffer} buf2 - Array buffer 2
 */
function arraybufferEqual(buf1, buf2) {
    if (buf1 === buf2) {
        return true;
    }

    if (buf1.byteLength !== buf2.byteLength) {
        return false;
    }

    var view1 = new DataView(buf1);
    var view2 = new DataView(buf2);

    var i = buf1.byteLength;
    while (i--) {
        if (view1.getUint8(i) !== view2.getUint8(i)) {
            return false;
        }
    }

    return true;
}

//exports
module.exports = encryptor;
},{"./enc-aescbc":2,"./hmac256":4,"./sha256":5}],4:[function(require,module,exports){
var sha256 = require('./sha256');

/**
 * HMAC 256 function
 * @param {Array<Byte>} key - The key
 */
var hmac256 = function (key) {
    var hashKey = key.slice(0),
        hash256 = new sha256(),
        service = {
            update: update,
            finalize: finalize
        };

    init();
    return service;

    function init() {
        var i;

        for (i = hashKey.length; i < 64; i++)
            hashKey[i] = 0;
        for (i = 0; i < 64; i++)
            hashKey[i] ^= 0x36;

        hash256.update(hashKey);
    }

    /*
       HMAC_SHA256_write: process a message fragment. 'msg' may be given as 
       string or as byte array and may have arbitrary length.
    */
    function update() {
        hash256.update(msg);
    }


    /*
       HMAC_SHA256_finalize: finalize the HMAC calculation. An array of 32 bytes
       (= 256 bits) is returned.
    */

    function finalize() {
        var i,
            md = hash256.finalize(),
            hash256New = new sha256();

        for (i = 0; i < 64; i++)
            hashKey[i] ^= 0x36 ^ 0x5c;

        hash256New.update(hashKey);
        hash256New.update(md);

        for (i = 0; i < 64; i++)
            hashKey[i] = 0;

        hashKey = undefined;
        
        return hash256New.finalize();
    }
};

//exports
module.exports = hmac256;
},{"./sha256":5}],5:[function(require,module,exports){
/*
 *  jssha256 version 0.1  -  Copyright 2006 B. Poettering
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */

/*
 * http://point-at-infinity.org/jssha256/
 *
 * This is a JavaScript implementation of the SHA256 secure hash function
 * and the HMAC-SHA256 message authentication code (MAC).
 *
 * The routines' well-functioning has been verified with the test vectors 
 * given in FIPS-180-2, Appendix B and IETF RFC 4231. The HMAC algorithm 
 * conforms to IETF RFC 2104. 
 *
 * The following code example computes the hash value of the string "abc".
 *
 *    SHA256_init();
 *    SHA256_write("abc");
 *    digest = SHA256_finalize();  
 *    digest_hex = array_to_hex_string(digest);
 * 
 * Get the same result by calling the shortcut function SHA256_hash:
 * 
 *    digest_hex = SHA256_hash("abc");
 * 
 * In the following example the calculation of the HMAC of the string "abc" 
 * using the key "secret key" is shown:
 * 
 *    HMAC_SHA256_init("secret key");
 *    HMAC_SHA256_write("abc");
 *    mac = HMAC_SHA256_finalize();
 *    mac_hex = array_to_hex_string(mac);
 *
 * Again, the same can be done more conveniently:
 * 
 *    mac_hex = HMAC_SHA256_MAC("secret key", "abc");
 *
 * Note that the internal state of the hash function is held in global
 * variables. Therefore one hash value calculation has to be completed 
 * before the next is begun. The same applies the the HMAC routines.
 *
 * Report bugs to: jssha256 AT point-at-infinity.org
 *
 */

/******************************************************************************/

/* array_to_hex_string: convert a byte array to a hexadecimal string */

// function array_to_hex_string(ary) {
//     var res = "";
//     for (var i = 0; i < ary.length; i++)
//         res += SHA256_hexchars[ary[i] >> 4] + SHA256_hexchars[ary[i] & 0x0f];
//     return res;
// }



/******************************************************************************/

/* The following lookup tables and functions are for internal use only! */

// SHA256_hexchars = new Array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
//     'a', 'b', 'c', 'd', 'e', 'f');

/******************************************************************************/

/* The following are the SHA256 routines */

/* 
   SHA256_init: initialize the internal state of the hash function. Call this
   function before calling the SHA256_write function.
*/
var sha256 = function () {
    var initH = new Array(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19),
        initK = new Array(
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ),
        buff = [],
        len = 0,
        service = {
            update: update,
            finalize: finalize
        };

    return service;

    /*
       SHA256_write: add a message fragment to the hash function's internal state. 
       'msg' - byte array and may have arbitrary length.
    
    */
    function update(msg) {
        buff = buff.concat(msg);
        for (var i = 0; i + 64 <= buff.length; i += 64)
            hashByteBlock(initH, buff.slice(i, i + 64));
        buff = buff.slice(i);
        len += msg.length;
    }


    /*
       SHA256_finalize: finalize the hash value calculation. Call this function
       after the last call to SHA256_write. An array of 32 bytes (= 256 bits) 
       is returned.
    */


    function finalize() {
        var i;
        buff[buff.length] = 0x80;

        if (buff.length > 64 - 8) {
            for (i = buff.length; i < 64; i++)
                buff[i] = 0;
            hashByteBlock(initH, buff);
            buff.length = 0;
        }

        for (i = buff.length; i < 64 - 5; i++)
            buff[i] = 0;
        buff[59] = (len >>> 29) & 0xff;
        buff[60] = (len >>> 21) & 0xff;
        buff[61] = (len >>> 13) & 0xff;
        buff[62] = (len >>> 5) & 0xff;
        buff[63] = (len << 3) & 0xff;
        hashByteBlock(initH, buff);

        var res = new Array(32);
        for (i = 0; i < 8; i++) {
            res[4 * i + 0] = initH[i] >>> 24;
            res[4 * i + 1] = (initH[i] >> 16) & 0xff;
            res[4 * i + 2] = (initH[i] >> 8) & 0xff;
            res[4 * i + 3] = initH[i] & 0xff;
        }

        initH = undefined;
        buff = undefined;
        len = undefined;
        
        return res;
    }

    function shasig0(x) {
        return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    function shasig1(x) {
        return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }

    function shaSig0(x) {
        return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^
            ((x >>> 22) | (x << 10));
    }

    function shaSig1(x) {
        return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^
            ((x >>> 25) | (x << 7));
    }

    function shaCh(x, y, z) {
        return z ^ (x & (y ^ z));
    }

    function shaMaj(x, y, z) {
        return (x & y) ^ (z & (x ^ y));
    }

    function hashWordBlock(H, W) {
        var i;
        for (i = 16; i < 64; i++)
            W[i] = (shasig1(W[i - 2]) + W[i - 7] +
                shasig0(W[i - 15]) + W[i - 16]) & 0xffffffff;
        var state = [].concat(H);
        for (i = 0; i < 64; i++) {
            var T1 = state[7] + shaSig1(state[4]) +
                shaCh(state[4], state[5], state[6]) + initK[i] + W[i];
            var T2 = shaSig0(state[0]) + shaMaj(state[0], state[1], state[2]);
            state.pop();
            state.unshift((T1 + T2) & 0xffffffff);
            state[4] = (state[4] + T1) & 0xffffffff;
        }
        for (i = 0; i < 8; i++)
            H[i] = (H[i] + state[i]) & 0xffffffff;
    }

    function hashByteBlock(H, w) {
        var W = new Array(16);
        for (var i = 0; i < 16; i++)
            W[i] = w[4 * i + 0] << 24 | w[4 * i + 1] << 16 |
                w[4 * i + 2] << 8 | w[4 * i + 3];
        hashWordBlock(H, W);
    }
};

//exports
module.exports = sha256;
},{}]},{},[1]);
