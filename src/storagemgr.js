var Utils = require('./utils');

/**
 * Manages file operations
 * @param {File} file - The disk file to be handled
 * @param {number} outputLength - The length of the output file
 */
var StorageManager = function (file, outputLength) {
    var readerIndex = 0,
        writerIndex = 0,
        reader = new FileReader(),
        fileSize = file.size,
        fileName = file.name,
        writer = new Uint8Array(outputLength);

    /**
     * Saves a blob to disk
     */
    var saveBlob = function (blob, fileName) {
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
        if (readerIndex >= fileSize) {
            return false;
        }
        var bSize = size;
        if (readerIndex + size > fileSize) {
            bSize = fileSize - readerIndex;
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
        reader.readAsArrayBuffer(file.slice(readerIndex, readerIndex + bSize));
        readerIndex += bSize;
        return true;
    };

    /**
     * Stores the provided data, calling the callback when done
     * @param {Uint8Array} data - The data to be stored
     * @param {Function} callback - The callback to be called when done
     */
    this.store = function (data, callback) {
        writer.set(data, writerIndex);
        writerIndex += typeof data.byteLength === typeof undefined ? data.length : data.byteLength;

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
     * Saves the currently stored data to disk
     * @param {boolean} addExt - True if should add the encryption extension
     */
    this.saveToDisk = function (addExt) {
        var blob;

        //if decrypted, the plain-text file will be smaller than the encrypted one
        if (writerIndex < writer.byteLength) {
            blob = new Blob([writer.slice(0, writerIndex)], {
                type: 'application/octet-stream'
            });
        }
        else {
            blob = new Blob([writer], {
                type: 'application/octet-stream'
            });
        }

        fileName = addExt ? fileName.concat('.smfw') : fileName.replace('.smfw', '');
        saveBlob(blob, fileName);
    };
};

//exports
module.exports = StorageManager;