const { KeyManager,
	deriveSeedFrom }		= require('@holo-host/wasm-key-manager');
const blake				= require('blakejs');
const multihash				= require('multihashes');
const base36				= require('base-x')("0123456789abcdefghijklmnopqrstuvwxyz");

const HOLO_HASH_AGENT_PREFIX		= new Uint8Array([0x84, 0x20, 0x24]);

function calc_dht_bytes ( pubkey ) {
    if ( pubkey.length !== 32 )
	throw new Error(`Unexpected pubkey length of ${pubkey.length}.  Should be 32 bytes`);

    const digest			= blake.blake2b( pubkey, null, 16 );
    const dht_part			= Buffer.from([digest[0], digest[1], digest[2], digest[3]])

    for (let i of [4, 8, 12]) {
	dht_part[0] ^= digest[i];
	dht_part[1] ^= digest[i + 1];
	dht_part[2] ^= digest[i + 2];
	dht_part[3] ^= digest[i + 3];
    }

    return dht_part;
}

const Codec = {
    "AgentId": {
	fromPublicKey: (buf) => {
	    return Buffer.concat([
		HOLO_HASH_AGENT_PREFIX,
		buf,
		calc_dht_bytes( buf )
	    ]);
	},
        decode: (str) => {
	    return Buffer.from(str.slice(1), "base64").slice(3,-4);
	},
        encode: (buf) => {
	    return "u" + Codec.AgentId.fromPublicKey(buf).toString("base64");
	},
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
