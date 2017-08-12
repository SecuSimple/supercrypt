var expect = require('chai').expect;
var encryptor = require('../src/encryptor');

describe('constructor', function () {
    it('should throw error when readBlock is not present', function () {
        expect(encryptor.bind(this)).to.throw("Exception. The 'readBlock' parameter was not present in the options");
    });

    it('should throw error when saveBlock is not present', function () {
        expect(encryptor.bind(this, { readBlock: {} })).to.throw("Exception. The 'saveBlock' parameter was not present in the options");
    });

    it('should throw error when fileSize is not present', function () {
        expect(encryptor.bind(this, { readBlock: {}, saveBlock: {} })).to.throw("Exception. The 'fileSize' parameter was not present in the options");
    });

    it('should throw error when finishHandler is not present', function () {
        expect(encryptor.bind(this, { readBlock: {}, saveBlock: {}, fileSize: 1 })).to.throw("Exception. The 'finishHandler' parameter was not present in the options");
    });

    it('should throw error when errorHandler is not present', function () {
        expect(encryptor.bind(this, { readBlock: {}, saveBlock: {}, fileSize: 1, finishHandler: {} })).to.throw("Exception. The 'errorHandler' parameter was not present in the options");
    });
});

describe('getEncryptedLength', function () {
    it('should get the encrypted length with padding 4b', function () {
        var len = encryptor.getEncryptedLength(4);
        expect(len).to.equal(64);
    });

    it('should get the encrypted length with padding 16b', function () {
        var len = encryptor.getEncryptedLength(16);
        expect(len).to.equal(80);
    });
});

describe('getDecryptedLength', function () {
    it('should get the decrypted length with padding', function () {
        var len = encryptor.getDecryptedLength(64);
        expect(len).to.equal(16);
    });
});

describe('encrypt', function () {
    this.slow(300);

    it('should call the readBlock handler', function (done) {
        var enc = new encryptor({
            readBlock: function () {
                done();
            },
            saveBlock: function () { },
            fileSize: 100,
            finishHandler: function () { },
            errorHandler: function () { }
        });

        enc.encrypt('testkey');
    });

    it('should throw an error when key is not provided', function () {
        var enc = new encryptor({
            readBlock: function () { },
            saveBlock: function () { },
            fileSize: 100,
            finishHandler: function () { },
            errorHandler: function () { }
        });

        expect(enc.encrypt).to.throw("Exception. The parameter 'key' was not present");
    });

    it('should call the continueEncryption handler - one block', function (done) {
        var read = 0;
        var arrData = Array.from({ length: 4 }, () => Math.floor(Math.random() * 9));
        var data = new Uint8Array(arrData);

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read === 1) {
                    return;
                }
                else {
                    read++;
                    cb(data);
                }
            },
            saveBlock: function () { },
            fileSize: 4,
            finishHandler: function () {
                done();
            },
            errorHandler: function () { }
        });

        enc.encrypt('testkey', [9, 4, 55, 666, 777, 989]);
    });

    it('should call the continueEncryption handler - two blocks', function (done) {
        var read = 0;
        var arrData = Array.from({ length: 160016 }, () => Math.floor(Math.random() * 9));
        var data = new Uint8Array(arrData);

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read === 2) {
                    return false;
                }

                if (read === 0) {
                    read++;
                    cb(data.slice(0, size));
                    return true;
                }
                else if (read === 1) {
                    read++;
                    cb(data.slice(size));
                    return true;
                }
            },
            saveBlock: function (d) { },
            fileSize: 160016,
            finishHandler: function () {
                done();
            },
            errorHandler: function () { }
        });

        enc.encrypt('testkey', [999, 998, 11, 12, 9, 4, 55, 666, 777, 989]);
    });

    it('should call the continueEncryption handler - no seedlist', function (done) {
        var read = false;
        var called = false;

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read) {
                    return false;
                }

                var data = new Uint8Array([1, 2, 3, 4]);
                read = true;
                cb(data);
                return true;
            },
            saveBlock: function () { },
            fileSize: 4,
            finishHandler: function () {
                expect(called).to.equal(true);
                done();
            },
            errorHandler: function () { },
            progressHandler: function () {
                called = true;
            }
        });

        enc.encrypt('testkey', []);
    });
});

describe('decrypt', function () {
    this.slow(300);

    it('should call the readBlock handler', function (done) {
        var enc = new encryptor({
            readBlock: function () {
                done();
            },
            saveBlock: function () { },
            fileSize: 100,
            finishHandler: function () { },
            errorHandler: function () { }
        });

        enc.decrypt('testkey');
    });

    it('should throw an error when key is not provided', function () {
        var enc = new encryptor({
            readBlock: function () { },
            saveBlock: function () { },
            fileSize: 100,
            finishHandler: function () { },
            errorHandler: function () { }
        });

        expect(enc.decrypt).to.throw("Exception. The parameter 'key' was not present");
    });

    it('should call the continueDecryption handler and decrypt successfully, calling progress handler', function (done) {
        var read = false;
        var called = false;
        var fullData = new Uint8Array([137, 217, 10, 109, 141, 103, 241, 204, 153, 62, 47, 97, 118, 113, 232, 249, 72, 9, 125, 45, 148, 122, 200, 175, 44, 3, 104, 82, 201, 177, 82, 164, 77, 232, 172, 133, 221, 38, 34, 117, 195, 142, 237, 149, 108, 148, 189, 84, 128, 106, 245, 171, 206, 86, 84, 125, 182, 32, 60, 148, 94, 35, 192, 119]);

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read) {
                    return false;
                }

                if (size === 16) {
                    cb(fullData.slice(0, 16));
                    return true;
                }
                else {
                    read = true;
                    cb(fullData.slice(16));
                    return true;
                }
            },
            saveBlock: function () { },
            fileSize: 64,
            finishHandler: function () {
                expect(called).to.equal(true);
                done();
            },
            errorHandler: function () { },
            progressHandler: function () {
                called = true;
            }
        });

        enc.decrypt('1234');
    });

    it('should call the continueDecryption handler with two blocks', function (done) {
        var read = 0;
        var called = false;

        var arrData = Array.from({ length: 160064 }, () => Math.floor(Math.random() * 9));
        var fullData = new Uint8Array(arrData);

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read === 3) {
                    return false;
                }

                if (read === 0) {
                    read++;
                    cb(fullData.slice(0, 16));
                    return true;
                }
                else if (read === 1) {
                    read++;
                    cb(fullData.slice(16, 160016));
                    return true;
                }
                else if (read === 2) {
                    read++;
                    cb(fullData.slice(160016));
                    return true;
                }
            },
            saveBlock: function () { },
            fileSize: 160064,
            finishHandler: function () {
            },
            errorHandler: function () {
                expect(called).to.equal(true);
                done();
            },
            progressHandler: function () {
                called = true;
            }
        });

        enc.decrypt('1234');
    });


    it('should throw error when key is wrong', function (done) {
        var read = false;
        var fullData = new Uint8Array([137, 217, 10, 109, 141, 103, 241, 204, 153, 62, 47, 97, 118, 113, 232, 249, 72, 9, 125, 45, 148, 122, 200, 175, 44, 3, 104, 82, 201, 177, 82, 164, 77, 232, 172, 133, 221, 38, 34, 117, 195, 142, 237, 149, 108, 148, 189, 84, 128, 106, 245, 171, 206, 86, 84, 125, 182, 32, 60, 148, 94, 35, 192, 119]);

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read) {
                    return;
                }

                if (size === 16) {
                    cb(fullData.slice(0, 16));
                }
                else {
                    read = true;
                    cb(fullData.slice(16));
                }
            },
            saveBlock: function () { },
            fileSize: 64,
            finishHandler: function () { },
            errorHandler: function (errCode) {
                if (errCode === 1) {
                    done();
                }
            }
        });

        enc.decrypt('12345');
    });

    it('should throw error when mac was altered', function (done) {
        var read = false;
        var fullData = new Uint8Array([137, 217, 10, 109, 141, 103, 241, 204, 153, 62, 47, 97, 118, 113, 232, 249, 72, 9, 125, 45, 148, 122, 200, 175, 44, 3, 104, 82, 201, 177, 82, 164, 77, 232, 172, 133, 221, 38, 34, 117, 195, 142, 237, 149, 108, 148, 189, 84, 128, 106, 245, 171, 206, 86, 84, 125, 182, 32, 60, 148, 94, 35, 192, 11]);

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read) {
                    return;
                }

                if (size === 16) {
                    cb(fullData.slice(0, 16));
                }
                else {
                    read = true;
                    cb(fullData.slice(16));
                }
            },
            saveBlock: function () { },
            fileSize: 64,
            finishHandler: function () { },
            errorHandler: function (errCode) {
                if (errCode === 1) {
                    done();
                }
            }
        });

        enc.decrypt('1234');
    });

    it('should read more if mac was read partially', function (done) {
        var read = 0;
        var fullData = new Uint8Array([137, 217, 10, 109, 141, 103, 241, 204, 153, 62, 47, 97, 118, 113, 232, 249, 72, 9, 125, 45, 148, 122, 200, 175, 44, 3, 104, 82, 201, 177, 82, 164, 77, 232, 172, 133, 221, 38, 34, 117, 195, 142, 237, 149, 108, 148, 189, 84, 128, 106, 245, 171, 206, 86, 84, 125, 182, 32, 60, 148, 94, 35, 192, 119]);

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read === 3) {
                    return;
                }

                if (read === 0) {
                    read++;
                    cb(fullData.slice(0, 16));
                }
                else if (read === 1) {
                    read++;
                    cb(fullData.slice(16, 48));
                }
                else {
                    read++;
                    cb(fullData.slice(48));
                }
            },
            saveBlock: function () { },
            fileSize: 64,
            finishHandler: function () {
                done();
            },
            errorHandler: function () { }
        });

        enc.decrypt('1234');
    });

    it('should read more if mac is the last block', function (done) {
        var read = 0;
        var fullData = new Uint8Array([137, 217, 10, 109, 141, 103, 241, 204, 153, 62, 47, 97, 118, 113, 232, 249, 72, 9, 125, 45, 148, 122, 200, 175, 44, 3, 104, 82, 201, 177, 82, 164, 77, 232, 172, 133, 221, 38, 34, 117, 195, 142, 237, 149, 108, 148, 189, 84, 128, 106, 245, 171, 206, 86, 84, 125, 182, 32, 60, 148, 94, 35, 192, 119]);

        var enc = new encryptor({
            readBlock: function (size, cb) {
                if (read === 3) {
                    return;
                }

                if (read === 0) {
                    read++;
                    cb(fullData.slice(0, 16));
                }
                else if (read === 1) {
                    read++;
                    cb(fullData.slice(16, 32));
                }
                else {
                    read++;
                    cb(fullData.slice(32));
                }
            },
            saveBlock: function () { },
            fileSize: 64,
            finishHandler: function () {
                done();
            },
            errorHandler: function () { }
        });

        enc.decrypt('1234');
    });
});