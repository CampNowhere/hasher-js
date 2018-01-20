/*
hasher.js - a library to generate hex-encoded hashes from UTF-8 strings
©2018 Jon Jenkins <jon@mj12.su>
MIT License

MD5 is the only hash supported thus far
*/
const UINT32MAX = Math.pow(2,32);
const UINT64MAX = Math.pow(2,64);

var tests = {
  "tests" : [
    {
      "input" : "0123456789ABCDEF",
      "md5_expected" : "e43df9b5a46b755ea8f1b4dd08265544"
    },
    {
      "input" : "El gato volador llegará mañana",
      "md5_expected" : "f540a23aabcff84f3c825512651a5346"
    },
    {
      "input" : "you can't have a metal band name without a ü character",
      "md5_expected" : "1a910b5df2f204331eb3ab2ddc5e2e2c"
    },
    {
      "input" : "now for a really messed up character: 𐍈",
      "md5_expected" : "d43d668f897edc7c27d79d88fb0f7089"
    },
    {
      "input" : "this is a longer message because we need to test the ability of the hashing functions to handle more than one block",
      "md5_expected" : "c198bfc5bb296324473d6c022ca7401d"
    },
    {
      "input" : "this is exactly one MD5 block because we need to test that too!!",
      "md5_expected" : "2ff9c3da9de6c9f83aefaff9b15dbf66"
    }
  ]
};

function test() {
  var outbox = document.getElementById("testOutput");
  var passed = 0;
  var total = tests.tests.length;
  for(tn in tests.tests) {
    t = tests.tests[tn];
    got = md5_hex(t.input);
    outbox.innerHTML += ("Input    : " + t.input + "\n");
    outbox.innerHTML += ("Got      : " + got + "\n");
    outbox.innerHTML += ("Expected : " + t.md5_expected + "\n");
    if(got != t.md5_expected)
    {
      outbox.innerHTML += ("Test failed :-(" + "\n");
    } else {
      outbox.innerHTML += ("Test passed!" + "\n");
      passed++;
    }
  }
  outbox.innerHTML += ("Passed "+ passed + " out of " + total + " tests."+ "\n");
}

//MD5
var md5_round_constants = [];
var md5_init_constants = [
  0x67452301,
  0xefcdab89,
  0x98badcfe,
  0x10325476
];

var md5_shift_amounts = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];


function md5_hex(s) {
  var inbin = utf8_to_bin(s);
  var th = md5(inbin);
  return binarray_to_hex_str(th);
}

function compute_md5_round_constants () {
  //md5 round constants
  for(i = 0; i < 64; i++) {
    md5_round_constants.push(
      Math.floor(
        UINT32MAX * Math.abs(
          Math.sin(i + 1)
        )
      )
    );
  }
}

function md5(ba) {
  // Take binarray and compute md5 checksum
  if(ba.type != "binarray") {
    throw("Must pass binarray to md5!");
  }
  if(md5_round_constants.length != 64) {
    compute_md5_round_constants();
  }
  var message_size = ba.size();
  var message_size_bits = message_size * 8;
  var message_size_block = int64_to_binarray(message_size_bits);
  message_size_block.reverse();
  ba.seek_end();
  ba.write(0x80);
  while(ba.size() % 64 != 56 ) {
    ba.write(0);
  }
  ba.write_block(message_size_block);
  if(ba.size() % 64 != 0) {
    throw("Invalid block size!");
  }
  ba.reset();
  var message_blocks = ba.size() / 64;
  var state = [];
  state[0] = md5_init_constants[0];
  state[1] = md5_init_constants[1];
  state[2] = md5_init_constants[2];
  state[3] = md5_init_constants[3];
  var i;
  for(i = 0; i < message_blocks; i++) {
    tb = ba.read_block(64);
    tb.reset();
    var blockarray = new Array();
    for(l = 0; l < 16; l++) {
      blockarray.push(binarray_to_int32(tb.read_block(4).reverse()));
    }
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    for(j = 0; j < 64; j++) {
      var f, g;
      if(j < 16) {
        f = uint32or(
          uint32and(b,c),
          uint32and(d,uint32not(b))
        );
        g = j;
      } else if(j < 32) {
        f = uint32or(
          uint32and(d,b),
          uint32and(c,uint32not(d))
        );
        g = ((5 * j) + 1) % 16;
      } else if(j < 48) {
        f = uint32xor(b,c,d);
        g = ((3 * j) + 5) % 16;
      } else {
        f = uint32xor(c,
          uint32or(b, uint32not(d))
        );
        g = (7 * j) % 16;
      }
      f = uint32addMod32(f, a, md5_round_constants[j], blockarray[g]);
      a = d;
      d = c;
      c = b;
      b = uint32addMod32(b, uint32rotateLeft(f,md5_shift_amounts[j]));
    }
    state[0] = uint32addMod32(state[0], a);
    state[1] = uint32addMod32(state[1], b);
    state[2] = uint32addMod32(state[2], c);
    state[3] = uint32addMod32(state[3], d);
  }
  var return_ba = new Binarray();
  return_ba.write_block(int32_to_binarray(state[0]).reverse());
  return_ba.write_block(int32_to_binarray(state[1]).reverse());
  return_ba.write_block(int32_to_binarray(state[2]).reverse());
  return_ba.write_block(int32_to_binarray(state[3]).reverse());
  return return_ba;
}


// Handling binary chicanery
function utf8_to_bin(s) { //Take a string and convert to Binarray
  ba = new Binarray();
  for(i = 0; i < s.length; i++) {
    cp = s.codePointAt(i);
    if(cp < 0x80) {
      ba.write(cp);
    } else if(cp < 0x800) {
      hibite = (cp & 0x3F) | 0x80;
      lobite = (cp >> 6) | 0xC0;
      ba.write(lobite);
      ba.write(hibite);
    } else if(cp < 0x10000) {
      hibite = (cp & 0x3F) | 0x80;
      midbite = ((cp >> 6) & 0x3F) | 0x80;
      lobite = (cp >> 12) | 0xE0;
      ba.write(lobite);
      ba.write(midbite);
      ba.write(hibite);
    } else if(cp < 0x110000) {
      hibite = (cp & 0x3F) | 0x80;
      midhibite = ((cp >> 6) & 0x3F) | 0x80;
      midbite = ((cp >> 12) & 0x3F) | 0x80;
      lobite = (cp >> 18) | 0xF0;
      ba.write(lobite);
      ba.write(midbite);
      ba.write(midhibite);
      ba.write(hibite);
      // Ignore surrogate pairs, because they're a mess. Seems to get it right
      // with anything I've thrown at it.
      i++;
    } else {
      throw("Codepoint out of range!");
    }
  }
  ba.reset();
  return ba;
}

function Binarray(){
  this.a = new Array();
  this.index = 0;
  this.type = 'binarray';
  this.write = function(b) {
    if(isNaN(b))
    {
      throw("Invalid data passed to Binarray");
    }
    if(this.index > this.size()) {
      this.a.push(b % 256);
      this.index = this.size();
    } else {
      this.a[this.index] = b % 256;
      this.index++;
    }
  };
  this.reset = function() {
    this.index = 0;
  };
  this.read = function() {
    if(this.index  >= this.size()) {
      return null;
    } else {
      return this.a[this.index++];
    }
  }
  this.size = function() {
    return this.a.length;
  }
  this.read_block = function (n) {
    if(isNaN(n)) {
      throw("Non-numeric valued passed to read_block!");
      return null;
    }
    var read_bytes = new Binarray();
    for (i = 0; (i < n) && (this.index < this.size()); i++) {
      read_bytes.write(this.read());
    }
    read_bytes.reset();
    return read_bytes;
  }
  this.write_block = function (b) {
    if(b.type != 'binarray') {
      throw("Can't write this to binarray!");
    }
    b.reset();
    while((a = b.read()) != null) {
      this.write(a);
    }
  }
  this.seek_end = function() {
    this.index = this.size();
  }
  this.seek = function(n) {
    if(n > this.size()) {
      return false;
    }
    this.index = n;
    return true;
  }
  this.reverse = function() {
    this.a = this.a.reverse();
    return this;
  }
}

function int32_to_binarray(n) {
  var ba = new Binarray()
  for(shifter = 24; shifter >= 0; shifter -= 8) {
    ba.write((n >>> shifter) & 0xFF);
  }
  return ba;
}

/*
Note: This is not a real int64 function. JS rounds numbers at 32 bits before
doing shifts, so we can't properly store an int64 without writing a helper function
to perform the shifting. So we're going to fake it here, and use the same 32 bit code,
except we're going to prepend 4 0x0 values.

"But what if I want to use this for a message bigger than 2^32 bits?"

Don't.
*/

function int64_to_binarray(n) {
  var ba = new Binarray()
  for(i = 0; i< 4; i++) {
    ba.write(0);
  }
  for(shifter = 24; shifter >= 0; shifter -= 8) {
    ba.write((n >>> shifter) & 0xFF);
  }
  return ba;
}

function binarray_to_int32(b) {
  //Big endian
  if(b.size() != 4) {
    throw("Binarray of incorrect size passed to binarray_to_int32!");
  }
  b.reset();
  b1 = b.read();
  b2 = b.read();
  b3 = b.read();
  b4 = b.read();
  a = uint32fromBytesBigEndian(b1,b2,b3,b4);
  return a;

}

function binarray_to_hex_str(b) {
  var c;
  var hexmap = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
  if(! b.size > 0) {
    return "";
  }
  ret_str = "";
  b.reset()
  while((c = b.read()) != null ) {
    ret_str += hexmap[(c & 0xF0) >> 4];
    ret_str += hexmap[(c & 0x0F)];
  }
  return ret_str;
}

// A big collection of helper functions, because JavaScript can't handle the
// monumental task of computing with unsigned integers.

function uint32fromBytesBigEndian(highByte, secondHighByte, thirdHighByte, lowByte) {
  return ((highByte << 24) | (secondHighByte << 16) | (thirdHighByte << 8) | lowByte) >>> 0;
}

function uint32or(uint32val0, argv) {
  var result = uint32val0;
  for (var index = 1; index < arguments.length; index += 1) {
    result = (result | arguments[index]);
  }
  return result >>> 0;
}

function uint32and(uint32val0, argv) {
  var result = uint32val0;
  for (var index = 1; index < arguments.length; index += 1) {
    result = (result & arguments[index]);
  }
  return result >>> 0;
}

function uint32xor(uint32val0, argv) {
  var result = uint32val0;
  for (var index = 1; index < arguments.length; index += 1) {
    result = (result ^ arguments[index]);
  }
  return result >>> 0;
}

function uint32not(uint32val) {
  return (~uint32val) >>> 0;
};

function uint32rotateLeft(uint32val, numBits) {
  return (((uint32val << numBits) >>> 0) | (uint32val >>> (32 - numBits))) >>> 0;
};

function uint32rotateRight(uint32val, numBits) {
  return (((uint32val) >>> (numBits)) | ((uint32val) << (32 - numBits)) >>> 0) >>> 0;
};

function uint32shiftRight(uint32val, numBits) {
  return uint32val >>> numBits;
}

function uint32addMod32(uint32val0/*, ...*/) {
  var result = uint32val0;
  for (var index = 1; index < arguments.length; index += 1) {
    result += arguments[index];
  }
  return result >>> 0;
}
