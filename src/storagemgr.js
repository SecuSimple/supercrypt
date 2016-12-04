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