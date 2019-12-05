const { KeyManager,
	deriveSeedFrom,
	from_hcs0, to_hcs0 }		= require('@holo-host/wasm-key-manager');
const multihash				= require('multihashes');

const Codec = {
    "AgentId": {
        decode: from_hcs0,
        encode: to_hcs0,
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
