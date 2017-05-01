var sha256 = require('./sha256');

/**
 * HMAC 256 function
 * @param {Array<Byte>} key - The key
 */
var hmac256 = function (key) {
    var hashKey = key.slice(0),
        hash256 = new sha256(),
        service = {
            update: update,
            finalize: finalize
        };

    init();
    return service;

    function init() {
        var i;

        for (i = hashKey.length; i < 64; i++)
            hashKey[i] = 0;
        for (i = 0; i < 64; i++)
            hashKey[i] ^= 0x36;

        hash256.update(hashKey);
    }

    /*
       HMAC_SHA256_write: process a message fragment. 'msg' may be given as 
       string or as byte array and may have arbitrary length.
    */
    function update(msg) {
        if (typeof msg.byteLength === typeof undefined) {
            hash256.update(msg);
        }
        else {
            hash256.updateByte(msg);
        }
    }


    /*
       HMAC_SHA256_finalize: finalize the HMAC calculation. An array of 32 bytes
       (= 256 bits) is returned.
    */

    function finalize() {
        var i,
            md = hash256.finalize(),
            hash256New = new sha256();

        for (i = 0; i < 64; i++)
            hashKey[i] ^= 0x36 ^ 0x5c;

        hash256New.update(hashKey);
        hash256New.update(md);

        for (i = 0; i < 64; i++)
            hashKey[i] = 0;

        hashKey = undefined;

        return hash256New.finalize();
    }
};

//exports
module.exports = hmac256;