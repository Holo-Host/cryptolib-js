
# Cross-compatible Cryptographic Utilities (Node/Web)

![](https://img.shields.io/npm/v/@holo-host/cryptolib/latest?style=flat-square)

Contains Holo specific key management implementation (`@holo-host/wasm-key-manager`); as well as
utilities for some internally standardized codecs (signatures, digests, and Agent IDs).

## Usage

```javascript
const crypto = require('crypto');
const expect = require('chai').expect;

const { Codec } = require('../src/index.js');

const sha256 = (buf) => crypto.createHash('sha256').update( Buffer.from(buf) ).digest();

const agentId = "HcScJip8RCjpuaamzwgSNAGHn5dxtdauzENQVU8g5XInxf65sxHMg9DSmkktbdr";
const publicKey = new Uint8Array([
 161, 222, 128, 146, 233, 128,  11,
 197,  77,  22,   0, 199, 102, 199,
 105,  12,  19, 193,  24, 250,  79,
 198, 221, 144, 203,  23, 155, 141,
 142, 179, 124, 113
]);

expect( Codec.AgentId.decode(agentId)  ).to.deep.equal(publicKey);


const agentId = "HcSCIaicaNCakbrhbaervczNbVha8eascijsiFixc6nbtgr5Drps6h3AKJ733ya";
const publicKey = new Uint8Array([
   1,   2,   3,   4,   5,   6,   7,
   8,   9,  10,  11,  12,  13,  14,
  15,  16,  17,  18,  19,  20,  21,
  22,  23,  24,  25,  26,  27,  28,
  29,  30,  31,  32
]);

expect( Codec.AgentId.encode(publicKey)   ).to.equal(agentId);

const messageBytes = Buffer.from("example 1");
const base64String = "ZXhhbXBsZSAx";

expect( Codec.Signature.decode(base64String) ).to.deep.equal(messageBytes)


const base64String = "ZXhhbXBsZSAy";
const messageBytes = Buffer.from("example 2");

expect( Codec.Signature.encode(messageBytes) ).to.equal(base64String);


const hashString = "QmNZAJfVYoCASiPc3uYZXrvhRFbxJLxG18R2Ga4ZXfP4kR";
const hashBytes = await sha256(new Uint8Array([0xca, 0xfe]));

expect( Codec.Digest.decode(hashString)).to.deep.equal(hashBytes);


const hashBytes = await sha256(new Uint8Array([0xba, 0xbe]));
const hashString = "QmeTu8d5sUNULwS72NxLNTMhLZfPma4qcWvG2LqxiUz1Gf";

expect( Codec.Digest.encode(hashBytes)).to.equal(hashString);

```
