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