/**
 * SHA 256 function
 */
var sha256 = function () {
    var initH = new Array(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19),
        initK = new Array(
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ),
        buff = [],
        len = 0,
        service = {
            update: update,
            updateByte: updateByte,
            finalize: finalize
        };

    return service;

    /*
       SHA256_write: add a message fragment to the hash function's internal state. 
       'msg' - byte array and may have arbitrary length.
    
    */
    function updateByte(msg) {
        var temp = new Uint8Array((buff.byteLength || buff.length) + msg.byteLength);
        temp.set(buff);
        temp.set(msg, buff.byteLength || buff.length);

        for (var i = 0; i + 64 <= temp.byteLength; i += 64) {
            hashByteBlock(initH, temp.slice(i, i + 64));
        }
        buff = temp.slice(i);
        len += msg.byteLength;
    }

    function update(msg) {
        buff = buff.concat(msg);
        for (var i = 0; i + 64 <= buff.length; i += 64)
            hashByteBlock(initH, buff.slice(i, i + 64));
        buff = buff.slice(i);
        len += msg.length;
    }


    /*
       SHA256_finalize: finalize the hash value calculation. Call this function
       after the last call to SHA256_write. An array of 32 bytes (= 256 bits) 
       is returned.
    */
    function finalize() {
        var i;

        if (typeof buff.byteLength !== typeof undefined) {
            //transforming buff into regular array
            buff = getArrayFromTypedArray(buff);
        }

        buff[buff.length] = 0x80;

        if (buff.length > 64 - 8) {
            for (i = buff.length; i < 64; i++)
                buff[i] = 0;
            hashByteBlock(initH, buff);
            buff.length = 0;
        }

        for (i = buff.length; i < 64 - 5; i++)
            buff[i] = 0;
        buff[59] = (len >>> 29) & 0xff;
        buff[60] = (len >>> 21) & 0xff;
        buff[61] = (len >>> 13) & 0xff;
        buff[62] = (len >>> 5) & 0xff;
        buff[63] = (len << 3) & 0xff;
        hashByteBlock(initH, buff);

        var res = new Array(32);
        for (i = 0; i < 8; i++) {
            res[4 * i + 0] = initH[i] >>> 24;
            res[4 * i + 1] = (initH[i] >> 16) & 0xff;
            res[4 * i + 2] = (initH[i] >> 8) & 0xff;
            res[4 * i + 3] = initH[i] & 0xff;
        }

        initH = undefined;
        buff = undefined;
        len = undefined;

        return res;
    }

    function getArrayFromTypedArray(typedArray) {
        var newArray = new Array(typedArray.byteLength);

        for (i = 0; i < newArray.length; i++) {
            newArray[i] = typedArray[i];
        }

        return newArray;
    }

    function shasig0(x) {
        return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    function shasig1(x) {
        return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }

    function shaSig0(x) {
        return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^
            ((x >>> 22) | (x << 10));
    }

    function shaSig1(x) {
        return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^
            ((x >>> 25) | (x << 7));
    }

    function shaCh(x, y, z) {
        return z ^ (x & (y ^ z));
    }

    function shaMaj(x, y, z) {
        return (x & y) ^ (z & (x ^ y));
    }

    function hashWordBlock(H, W) {
        var i;
        for (i = 16; i < 64; i++)
            W[i] = (shasig1(W[i - 2]) + W[i - 7] +
                shasig0(W[i - 15]) + W[i - 16]) & 0xffffffff;
        var state = [].concat(H);
        for (i = 0; i < 64; i++) {
            var T1 = state[7] + shaSig1(state[4]) +
                shaCh(state[4], state[5], state[6]) + initK[i] + W[i];
            var T2 = shaSig0(state[0]) + shaMaj(state[0], state[1], state[2]);
            state.pop();
            state.unshift((T1 + T2) & 0xffffffff);
            state[4] = (state[4] + T1) & 0xffffffff;
        }
        for (i = 0; i < 8; i++)
            H[i] = (H[i] + state[i]) & 0xffffffff;
    }

    function hashByteBlock(H, w) {
        var W = new Array(16);
        for (var i = 0; i < 16; i++)
            W[i] = w[4 * i + 0] << 24 | w[4 * i + 1] << 16 |
                w[4 * i + 2] << 8 | w[4 * i + 3];
        hashWordBlock(H, W);
    }
};

//exports
module.exports = sha256;