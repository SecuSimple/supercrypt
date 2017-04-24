var Utils = require('./utils');

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
     * @param {Function} callback - The callback to be called when done
     */
    this.store = function (data, callback) {
        writer = writer.concat(data);

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
        var blob = new Blob([Utils.toTypedArray(writer)], {
            type: 'application/octet-stream'
        });

        fileName = addExt ? fileName.concat('.smfw') : fileName.replace('.smfw', '');
        saveBlob(blob, fileName);
    };
};

//exports
module.exports = StorageManager;