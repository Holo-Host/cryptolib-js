const { KeyManager,
	deriveSeedFrom,
	from_hcs0, to_hcs0 }		= require('@holo-host/wasm-key-manager');
const multihash				= require('multihashes');
const base36				= require('base-x')("0123456789abcdefghijklmnopqrstuvwxyz");

const Codec = {
    "AgentId": {
        decode: from_hcs0,
        encode: to_hcs0,
    },
    "Base36": {
	decode: (str) => base36.decode(str),
	encode: (buf) => base36.encode(Buffer.from(buf)),
    },
    "Signature": {
        decode: (str) => Buffer.from(str, 'base64'),
        encode: (buf) => Buffer.from(buf).toString('base64'),
    },
    "Digest": {
        decode: (str) => multihash.decode(multihash.fromB58String(str)).digest,
        encode: (buf) => multihash.toB58String(multihash.encode(Buffer.from(buf), 'sha2-256')),
    },
};

module.exports = {
    KeyManager,
    deriveSeedFrom,
    Codec,
};
