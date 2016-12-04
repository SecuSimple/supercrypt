(function (root) {
    var encryptor = function (options) {
        var algorithm,
            readChecksum,
            chunkSize = 160000,
            service = {
                encrypt: encrypt,
                decrypt: decrypt
            },
            defaultOps = {
                algorithm: root.sEncrypt.Encryptors.AESCBC,
                keyLength: 256
            };

        checkOptions();
        return service;

        /**
         * Initializes the encryptor
         */
        function checkOptions() {
            extend(options, defaultOps);

            if (!options.readBlock) {
                throw "The 'readBlock' parameter was not present in the options";
            }

            if (!options.saveBlock) {
                throw "The 'saveBlock' parameter was not present in the options";
            }

            if (!options.finishHandler) {
                throw "The 'finishHandler' parameter was not present in the options";
            }

            if (!options.errorHandler) {
                throw "The 'errorHandler' parameter was not present in the options";
            }
        }

        /**
         * Encrypts a byte block
         * 
         * @param {Uint8Array} block - The block to encrypt
         * @returns {Array<Byte>} The encrypted block
         */
        function encrypt(key, seedList) {
            if (!key) {
                throw "The parameter 'key' was not present";
            }

            //generating and saving the IV
            var iv = generateIV(seedList);
            options.saveBlock(iv);

            //transforming the key
            key = stringToByteArray(key, options.keyLength / 8);

            //instantiating the algorithm
            algorithm = new options.algorithm(key, iv, options.keyLength);

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
            options.saveBlock(block);

            //check if there's more to read
            if (!options.readBlock(chunkSize, continueEncryption)) {

                //save the checksum and call the finish handler
                options.saveBlock(stringToByteArray(algorithm.getChecksum(), 16), true);
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
                throw "The parameter 'key' was not present";
            }

            options.readBlock(32, function (data) {
                readChecksum = byteArrayToString(data.slice(0, 16));
                iv = data.slice(16);

                //transforming the key
                key = stringToByteArray(key, options.keyLength / 8);

                //instantiating the algorithm
                algorithm = new options.algorithm(key, iv, options.keyLength);

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
            if (options.progressHandler) {
                options.progressHandler(block.byteLength);
            }

            //decrypt the block and save
            block = algorithm.decrypt(block);
            options.saveBlock(block);
            if (!options.readBlock(chunkSize, continueDecryption)) {

                //validate the checksum
                if (readChecksum === algorithm.getChecksum()) {
                    var removedBytes = block[block.length - 1];
                    options.finishHandler(removedBytes);
                } else {
                    options.errorHandler(1);
                }
            }
        }
    }

    /**
     * Transforms a string into a fixed size byte array
     * @param {String} string - the string to be transformed
     * @param {Number} len - the desired destination length
     * @return {Array} The resulting array padded with 0 at the end
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
     * @return {String} The resulting string
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

    //exposing the encryptor class
    root.sEncrypt.Encryptor = encryptor;
})(this);