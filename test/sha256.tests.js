var expect = require('chai').expect;
var sha = require('../src/sha256');

describe('constructor', function () {
    it('should create hash', function () {
        var sha256 = new sha();
        sha256.update('test');
        var result = sha256.finalize();

        expect(result).to.have.same.members([207, 43, 27, 110, 44, 48, 134, 33, 252, 224, 111, 211, 226, 83, 4, 112, 117, 84, 146, 193, 130, 168, 9, 64, 0, 229, 82, 119, 220, 194, 48, 135]);
    });

    it('should create hash', function () {
        var sha256 = new sha();
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        sha256.update('123');
        var result = sha256.finalize();

        expect(result).to.have.same.members([162, 100, 81, 104, 232, 77, 181, 242, 47, 80, 148, 151, 174, 199, 203, 35, 242, 161, 164, 188, 192, 114, 15, 15, 244, 243, 98, 175, 69, 217, 120, 195]);
    });
});