'use script';

let native = require('native');

// TODO: make Hash a transform stream
class Hash {
    constructor(type, key) {
        if (key instanceof KeyObject) {
            key = key.key;
        }
        this._native = native.createCryptoHash(this, type, key);
    }

    update(data, encoding) {
        if (typeof data === 'string')
            data = Buffer.from(data, encoding);

        native.cryptoHashUpdate(this._native, data);
        return this;
    }

    digest(encoding) {
        let val = native.cryptoHashDigest(this._native);
        if (encoding)
            return val.toString(encoding);
        else
            return val;
    }
}

exports.randomBytes = native.randomBytes;


class KeyObject {
    constructor(key, encoding, type) {
        this.key = key;
        this.encoding = encoding;
        this.type = type;
    }
}

exports.KeyObject = KeyObject;
exports.createSecretKey = function(key, encoding) {
    return new KeyObject(key, encoding, 'secret');
}

exports.createHash = function (type) {
    return new Hash(type);
}

exports.createHmac = function (type, key) {
    return new Hash(type, key);
}

exports.randomFillSync = function(buffer, offset, size) {
    if(offset === undefined)
        offset = 0;
    if(size === undefined)
        size = buffer.length - offset;

    let buf = native.randomBytes(size);
    buf.copy(buffer, offset);
}

// TODO: use second core
exports.randomFill = function(buffer, offset, size, callback) {
    if(callback === undefined) {
        if(size === undefined) {
            callback = offset;
            offset = undefined;
        } else {
            callback = size;
            size = undefined;
        }
    }

    if(offset === undefined)
        offset = 0;
    if(size === undefined)
        size = buffer.length - offset;

    let buf = native.randomBytes(size);
    buf.copy(buffer, offset);

    process.nextTick(() => {
        callback(null, buffer);
    });
}