var expect = require('chai').expect;
var enc = require('../src/enc-aescbc');

describe('constructor', function () {
    it('should work with 16b key', function () {
        var encr = new enc.AESCBC('1234567890123456', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 45, 16, 4]);
    });

    it('should work with 24b key', function () {
        var encr = new enc.AESCBC('123456789012345678901234', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 45, 16, 4]);
    });

    it('should work with 32b key', function () {
        var encr = new enc.AESCBC('12345678901234567890123456789012', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 45, 16, 4]);
    });

    it('should throw error with non-standard key length', function () {
        var create = function () {
            var encr = new enc.AESCBC('123456789012345678901234567890123', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 45, 16, 4]);
        };

        expect(create).to.throw("Key error: Only key lengths of 16, 24 or 32 bytes allowed!");
    });
});