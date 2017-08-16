var sha256 = require('./sha256');

/**
 * HMAC 256 function
 * @param {Array<Byte>} key - The key
 */
var hmac256 = function (key) {
    var hashKey = key.slice(0),
        hash256 = new sha256(),
        hashSize = 64,
        service = {
            update: update,
            finalize: finalize
        };

    init();
    return service;

    /**
     * Initializes the hash
     */
    function init() {
        var i;

        for (i = hashKey.length; i < hashSize; i++)
            hashKey[i] = 0;
        for (i = 0; i < hashSize; i++)
            hashKey[i] ^= 0x36;

        hash256.update(hashKey);
    }

    
    /**
     * Updates the HMAC with a new message
     * @param {any} msg - The message as string or byte array
     */
    function update(msg) {
        //check the message type (string or byte array)
        if (typeof msg.byteLength === typeof undefined) {
            hash256.update(msg);
        }
        else {
            hash256.updateByte(msg);
        }
    }
    
    /**
     * Finalizes the HMAC calculation
     * @returns {Array<byte>} A byte array
     */
    function finalize() {
        var i,
            md = hash256.finalize(),
            hash256New = new sha256();

        for (i = 0; i < hashSize; i++)
            hashKey[i] ^= 0x36 ^ 0x5c;

        hash256New.update(hashKey);
        hash256New.update(md);

        for (i = 0; i < hashSize; i++)
            hashKey[i] = 0;

        hashKey = undefined;

        return hash256New.finalize();
    }
};

//exports
module.exports = hmac256;