'use script';

let native = require('native');
let Writable = require('stream').Writable;

// TODO: make Hash a transform stream
class Hash extends Writable {
    constructor(type, key, options) {
        super(options);
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

    _write(data, encoding, done) {
        this.update(data, encoding);
        if (done)
            done();
    }
}

exports.randomBytes = native.randomBytes;


class KeyObject {
    constructor(key, encoding, type) {
        this.key = key;
        this.encoding = encoding;
        this.type = type;
        this._native = native.createCryptoKeyObject(this, type == 'secret' ? 2 : type == 'private' ? 1 : 3, key);
    }
}

exports.KeyObject = KeyObject;
exports.createSecretKey = function(key, encoding) {
    return new KeyObject(key, encoding, 'secret');
}

exports.createPrivateKey = function(key, encoding) {
    return new KeyObject(key, encoding, 'private');
}

exports.createPublicKey = function(key, encoding) {
    return new KeyObject(key, encoding, 'public');
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

class Sign extends Hash {
    constructor(algorithm, options) {
        super(algorithm, undefined, options);
        this.algorithm = algorithm;
    }

    sign(key, encoding) {
        if (!(key instanceof KeyObject)) {
            key = exports.createPrivateKey(key);
        }
        let hash = this.digest();
        let signature = native.cryptoSign(key._native, hash, this.algorithm);
        if (encoding)
            return signature.toString(encoding);
        else
            return signature;
    }
}

exports.createSign = function(algorithm, options) {
    if (algorithm.startsWith('RSA-')) {
        algorithm = algorithm.substr(4);
    }
    return new Sign(algorithm, options);
}