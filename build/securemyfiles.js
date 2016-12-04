(function (root) {
  (function(root){
      root.sEncrypt = {
          Encryptors: {}
      };
  })(this);
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
  (function(root) {

      /**
       * Initializes a new AES CBC encryptor
       * @constructor
       * @param {Array<Byte>} key - The encryption key
       * @param {Array<Byte>} iv - The initialization vector
       * @param {Number} keyLength - The encryption key desired length
       */
      var EncryptorAESCBC = function(key, iv, keyLength) {
          var encryptor = {
              chunkSize: 160000,
              encrypt: encrypt,
              decrypt: decrypt,
              getChecksum: getChecksum,
          },
              prevEncBlock = iv,
              prevDecBlock = iv,
              checksum = 0,
              key,
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
                  if (endIndex > byteArray.byteLength) {
                      endIndex = byteArray.byteLength;
                  }
                  encBlock = [];
                  for (eidx = 0, idx = startIndex; idx < endIndex; eidx++ , idx++) {
                      encBlock[eidx] = byteArray[idx];
                  }

                  //pad the last bytes if needed
                  if (eidx < 16) {
                      paddingValue = 16 - eidx;
                      while (eidx < 16) {
                          encBlock[eidx++] = paddingValue;
                      }
                  }

                  checksum = checksum ^ cksum(encBlock);
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
                  if (endIndex > byteArray.byteLength) {
                      endIndex = byteArray.byteLength;
                  }

                  decBlock = [];
                  for (eidx = 0, idx = startIndex; idx < endIndex; eidx++ , idx++) {
                      decBlock[eidx] = byteArray[idx];
                  }

                  blockBefore = decBlock.slice(0);
                  decryptBlock(decBlock, key);
                  xor(decBlock, prevDecBlock);
                  checksum = checksum ^ cksum(decBlock);

                  prevDecBlock = blockBefore;

                  for (eidx = 0, idx = resultArray.length; eidx < 16; eidx++ , idx++) {
                      resultArray[idx] = decBlock[eidx];
                  }

                  startIndex += 16;
              }
              return resultArray;
          }

          /**
           * Returns the checksum
           * @returns {String} - the checksum as string
           */
          function getChecksum() {
              return checksum.toString();
          }

          /**
           * Computes simple checksum of a byte array
           * @param {Array<Byte>} byteArray - The byte array
           * @return {Number} The checksum
           */
          function cksum(byteArray) {
              var res = 0,
                  len = byteArray.length;
              for (var i = 0; i < len; i++) {
                  res = res * 31 + byteArray[i];
              }
              return res;
          }

          /**
           * Applies XOR on two arrays having a fixed length of 16 bytes.
           * @param {Array<Byte>} arr1 - The first array
           * @param {Array<Byte>} arr2 - The second array
           * @return {Array<Byte>} The result array
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

      //registering encryptor
      root.sEncrypt.Encryptors.AESCBC = EncryptorAESCBC;
  })(this);
  /**
   * Manages file operations
   * @param {File} file - The disk file to be handled
   */
  var StorageManager = function (file) {
      var index = 0,
          reader = new FileReader(),
          fileSize = file.size,
          fileName = file.name,
          writer = [],
          length = fileSize - 32;

      /**
       * IE - Saves a blob to disk
       */
      var msSaveAs = typeof navigator !== "undefined" &&
          navigator.msSaveOrOpenBlob && navigator.msSaveOrOpenBlob.bind(navigator);

      /**
       * Webkit - Saves a blob to disk
       */
      var wkSaveAs = typeof webkitRequestFileSystem !== 'undefined' &&
          function (blob, fileName) {
              webkitRequestFileSystem(TEMPORARY, length, function (fs) {
                  fs.root.getDirectory("SecureMyFiles", {
                      create: true
                  }, function (dir) {
                      var save = function () {
                          dir.getFile(fileName, {
                              create: true,
                              exclusive: false
                          }, function (file) {
                              file.createWriter(function (writer) {
                                  writer.onwriteend = function (event) {
                                      window.location.href = file.toURL();
                                  };
                                  writer.write(blob);
                              });
                          });
                      };

                      dir.getFile(fileName, {
                          create: false
                      }, function (file) {
                          file.remove(save);
                      }, function () {
                          save();
                      });

                  });
              });
          };

      /**
       * Saves a blob to disk
       */
      var defaultSaveAs = function (blob, fileName) {
          var objUrl = URL.createObjectURL(blob);

          var a = document.createElement("a");
          a.style = "display: none";
          document.body.appendChild(a);

          a.href = objUrl;
          a.download = fileName;
          a.click();
          setTimeout(function () {
              URL.revokeObjectURL(objUrl);
          }, 0);
      };

      /**
       * Reads the next specific number of bytes, calling the callback when done
       * @param {Number} size - The number of bytes to be read
       * @param {Function} callback - The callback to be called when done
       */
      this.readChunk = function (size, callback) {
          if (index >= fileSize) {
              return false;
          }
          var bSize = size;
          if (index + size > fileSize) {
              bSize = fileSize - index;
          }
          reader.onload = function (e) {
              if (reader.readyState === 2) {
                  var block = new Uint8Array(reader.result);
                  if (typeof callback === 'function') {
                      setTimeout(function () {
                          callback(block);
                      }, 5);
                  }
              }
          };
          reader.readAsArrayBuffer(file.slice(index, index + bSize));
          index += bSize;
          return true;
      };

      /**
       * Stores the provided data, calling the callback when done
       * @param {Uint8Array} data - The data to be stored
       * @param {Boolean} prepend - The data will be prepended
       * @param {Function} callback - The callback to be called when done
       */
      this.store = function (data, prepend, callback) {
          writer = prepend ? data.concat(writer) : writer.concat(data);

          if (typeof callback === 'function') {
              callback();
          }
      };

      /**
       * Gets the file length
       * @return {Number} The file length
       */
      this.getLength = function () {
          return fileSize;
      };

      /**
       * Returns the final data
       */
      this.getData = function (removedBytes) {
          return Utils.toTypedArray(writer, length - removedBytes);
      };

      /**
       * Saves the currently stored data to disk
       */
      this.saveToDisk = function (removedBytes) {
          var saveAs = msSaveAs || wkSaveAs || defaultSaveAs,
              blob = new Blob([Utils.toTypedArray(writer, length - removedBytes)], {
                  type: 'application/octet-stream'
              });

          fileName = length ? fileName.replace('.smfw', '') : fileName.concat('.smfw');
          saveAs(blob, fileName);
      };
  };
  var Utils = {};


  /**
   * Transforms a regular array into a typed array
   * @param {Array} array - the array to be copied
   */
  Utils.toTypedArray = function (array, length) {
    var mLen = length ? Math.min(array.length, length) : array.length;
    var result = new Uint8Array(mLen);
    for (var i = mLen - 1; i >= 0; i--) {
      result[i] = array[i];
    }
    return result;
  };

  /**
   * Transforms a string into a fixed size byte array
   * @param {String} string - the string to be transformed
   * @param {Number} len - the desired destination length
   * @return {Array} The resulting array padded with 0 at the end
   */
  Utils.stringToByteArray = function (string, len) {
    if (string.length > len) {
      throw 'String is too large';
    }

    var lengthArray = new Array(len);
    for (var i = string.length - 1, j = len - 1; i >= 0; i--, j--) {
      lengthArray[j] = string.charCodeAt(i);
    }

    while (j >= 0) {
      lengthArray[j--] = 0;
    }
    return lengthArray;
  };

  /**
   * Transforms a byte array into string
   * @param {TypedArray} byteArray - the typed byte array to be transformed
   * @return {String} The resulting string
   */
  Utils.byteArrayToString = function (byteArray) {
    var string = '';
    for (var i = 0; i < byteArray.byteLength; i++) {
      if (byteArray[i] === 0) {
        continue;
      }

      string += String.fromCharCode(byteArray[i]);
    }
    return string;
  };


  /**
   * Initializes the random number generator
   */
  Utils.RandomGenerator = function () {
    var attached = false,
      entropy = [];

    /**
     * Initializes the generator
     */
    var checkEvents = function () {
      if (typeof document === 'undefined') {
        return;
      }

      if (!attached && entropy.length <= 102400) {
        document.addEventListener('mousemove', collectEntropy);
        attached = true;
      } else if (attached && entropy.length > 102400) {
        document.removeEventListener('mousemove', collectEntropy);
        attached = false;
      }
    };

    /**
     * Collects entropy from user
     */
    var collectEntropy = function (e) {
      entropy.push(e.screenX);
      entropy.push(e.screenY);
      checkEvents();
    };

    /**
     * Generate new random 128-bit key, based on entropy
     */
    this.generate = function () {
      var ent, dat, num, result = [];
      for (var i = 0; i < 16; i++) {
        ent = entropy.length > 1 ? entropy.splice(i, 2) : [Math.random() * 10, Math.random() * 10];
        dat = new Date();
        num = (ent.length === 2) ? ((ent[0] * Math.random() + ent[1] * Math.random()) / 10) : (Math.random() * 10 + Math.random() * 100 + Math.random() * 1000) / 100;

        result[i] = parseInt(num * dat.getMilliseconds() / 10);
        while (result[i] > 255) {
          result[i] -= 255;
        }
      }

      checkEvents();
      return result;
    };

    checkEvents();
  };

  /**
   * Main Secure My Files (SMF) class - creates a new SMF object
   * @constructor
   * @param {Function} success - The success callback
   * @param {Function} error - The error callback
   */
  var SecureMyFiles = function (success, error, progress, saveOnDisk) {
      var rGen = new Utils.RandomGenerator(),
          sMan,
          encryptor;

      if (typeof success !== 'function' || typeof error !== 'function') {
          throw 'Success and Error callbacks are mandatory and must be functions!';
      }

      var handleProgress = function (processed) {
          if (typeof progress === 'function') {
              progress(processed, sMan.getLength());
          }
      };

      var handleFinish = function (removedBytes) {
          sMan.saveToDisk(removedBytes);
      };

      this.encryptFile = function (file, key) {
          var seedList = [];//TODO use random generator
          sMan = new StorageManager(file);
          encryptor = new sEncrypt.Encryptor({
              saveBlock: sMan.store,
              readBlock: sMan.readChunk,
              progressHandler: handleProgress,
              finishHandler: handleFinish,
              errorHandler: error
          });

          encryptor.encrypt(key, seedList);
      };

      this.decryptFile = function (file, key) {
          sMan = new StorageManager(file);
          encryptor = new sEncrypt.Encryptor({
              saveBlock: sMan.store,
              readBlock: sMan.readChunk,
              progressHandler: handleProgress,
              finishHandler: handleFinish,
              errorHandler: error
          });

          encryptor.decrypt(key);
      };
  };

  //exposing the namespace
  if (typeof exports !== 'undefined') { //exports
    exports.smf = SecureMyFiles;
  } else if (typeof define === 'function' && define.amd) { //AMD
    define('smf', [], function () {
      return SecureMyFiles;
    });
  } else {
    root.smf = SecureMyFiles; //global 
  }
})(this);