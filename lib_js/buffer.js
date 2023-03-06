Buffer = ((oldFunc) => {
    let newBuffer = function (...args) {
        if(typeof args[0] === 'string' && (args[1] == 'hex' || args[1] == 'base64'))
            return oldFunc.call(this, Duktape.dec(args[1], args[0]));
        else if(args[0].slice && typeof args[1] !== 'string' && args[2] !== undefined)
	    // Workaround: DukTape does not allow slicing in constructor
            return oldFunc.call(this, args[0].slice(args[1], args[1] + args[2]));
	else
            return oldFunc.call(this, ...args);
    }
    newBuffer.byteLength = oldFunc.byteLength;
    newBuffer.compare = oldFunc.compare;
    newBuffer.concat = oldFunc.concat;
    newBuffer.isBuffer = oldFunc.isBuffer;
    newBuffer.isEncoding = oldFunc.isEncoding;
    newBuffer.poolSize = oldFunc.poolSize;
    newBuffer.prototype = oldFunc.prototype;

    // Not implemented by DukTape
    newBuffer.from = (...args) => { return new newBuffer(...args); }
    newBuffer.allocUnsafe = newBuffer.alloc = (...args) => { return new newBuffer(...args); }
    return newBuffer;
})(Buffer);

Buffer.prototype.toString = ((oldFunc) => {
    return function (encoding, b, c) {
        if (encoding == 'hex' || encoding == 'base64')
            return Duktape.enc(encoding, this);
        else
            return oldFunc.call(this, encoding, b, c);
    }
})(Buffer.prototype.toString);

Buffer.prototype.subarray = ((oldFunc) => {
    // Make sure the return value of subarray is a buffer, not a Uint8Array
    return function (offset, len) {
        var retval = oldFunc.call(this, offset, len);
        retval.__proto__=this.__proto__;
        return retval;
    }
})(Buffer.prototype.subarray);

Uint8Array.prototype.indexOf = function (needle) {        
    for (var i = 0; i < this.length; i++) {
        if (this[i] == needle) {
            return i;
        }
    }        
    return -1;        
};

Uint8Array.prototype.lastIndexOf = function (needle) {        
    for (var i = this.length - 1; i >= 0 ; i--) {
        if (this[i] == needle) {
            return i;
        }
    }        
    return -1;        
};

Uint8Array.prototype.equals = function (array) {        
    if (this.length !== array.length) {
        return false;
    }
    for (var i = 0; i < this.length; i++) {
        if (this[i] !== array[i]) {
            return false;
        }
    }        
    return true;        
};

Uint8Array.prototype.readUIntLE = function(offset, len) {
    offset = offset >>> 0;
    len = len >>> 0;
  
    var retval = this[offset];
    var mult = 1;
    for (var i = 0; i < len; i++) {
        mult <<= 2;
        retval += this[offset + i] * mult;
    }    
  
    return retval;
};

Uint8Array.prototype.readIntLE = function(offset, len) {
    offset = offset >>> 0;
    len = len >>> 0;
  
    var retval = this[offset];
    var mult = 1;
    for (var i = 0; i < len; i++) {
        mult <<= 2;
        retval += this[offset + i] * mult;
    }    

    if (retval >= mult * 0x80) {
        retval -= Math.pow(2, 8 * byteLength);
    }
  
    return retval;
}

Uint8Array.prototype.reverse = function () {            
    var len = this.length;
    var middle = Math.floor(len / 2);    
    for (var index = 0; index < middle; index++) {
      var value = this[index];
      this[index] = this[len - index - 1];
      this[len - index - 1] = value;
    } return this;
};

Uint8Array.prototype.map = function (exp, thisArg) {            
    var retval = new Uint8Array(this.length);
    for (var i = 0; i < this.length; i++) {
        retval[i] = exp.call(thisArg, this[i], i, this);
    }
    retval.__proto__=this.__proto__;
    return retval;
};

exports.Buffer = Buffer;
exports.SlowBuffer = Buffer;
