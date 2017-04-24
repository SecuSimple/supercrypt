var sEncryptor = require('../sEncrypt/sEncrypt');
var StorageManager = require('./storagemgr');
var Utils = require('./utils');

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

    var handleFinish = function (addExt) {
        sMan.saveToDisk(addExt);
    };

    this.encryptFile = function (file, key) {
        var seedList = [];//TODO use random generator
        sMan = new StorageManager(file);
        encryptor = new sEncryptor({
            fileSize: sMan.getLength(),
            saveBlock: sMan.store,
            readBlock: sMan.readChunk,
            progressHandler: handleProgress,
            finishHandler: handleFinish.bind(this, true),
            errorHandler: error
        });

        encryptor.encrypt(key, seedList);
    };

    this.decryptFile = function (file, key) {
        sMan = new StorageManager(file);
        encryptor = new sEncryptor({
            fileSize: sMan.getLength(),
            saveBlock: sMan.store,
            readBlock: sMan.readChunk,
            progressHandler: handleProgress,
            finishHandler: handleFinish,
            errorHandler: error,
        });

        encryptor.decrypt(key);
    };
};

//exports
module.exports = SecureMyFiles;