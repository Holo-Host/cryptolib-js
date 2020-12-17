const { KeyManager,
	deriveSeedFrom }		= require("@holo-host/wasm-key-manager");
const blake				= require("blakejs");
const multihash				= require("multihashes");
const base36				= require("base-x")("0123456789abcdefghijklmnopqrstuvwxyz");

const HOLO_HASH_AGENT_PREFIX		= Buffer.from(new Uint8Array([0x84, 0x20, 0x24]).buffer);
const HOLO_HASH_HEADER_PREFIX		= Buffer.from(new Uint8Array([0x84, 0x29, 0x24]).buffer);
const HOLO_HASH_ENTRY_PREFIX		= Buffer.from(new Uint8Array([0x84, 0x21, 0x24]).buffer);
const HOLO_HASH_DNA_PREFIX		  = Buffer.from(new Uint8Array([0x84, 0x2d, 0x24]).buffer);

const getHoloHashPrefix = holoHashType => {
	let holoHashPrefix;
	switch (holoHashType) {
		case "header":
			holoHashPrefix = HOLO_HASH_HEADER_PREFIX;
			break;
		case "entry":
			holoHashPrefix = HOLO_HASH_ENTRY_PREFIX;
			break;
		case "dna":
			holoHashPrefix = HOLO_HASH_DNA_PREFIX;
			break;
		default:
			throw new Error("Received unsupported HoloHash Type in Codec.Digest : ", holoHashType);
	}
	return holoHashPrefix;
}

function check_pub_key_length (pubkey) {
	if (Buffer.byteLength(pubkey) !== 32)
		throw new Error(`Unexpected pubkey length of ${Buffer.byteLength(pubkey)}.  Should be 32 bytes`);
	return pubkey;
}

// Generate holohash 4 byte (or u32) dht "location" - used for checksum and dht sharding
function calc_dht_bytes ( data ) {
	const digest				= blake.blake2b( data, null, 16 );
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
		holoHashFromPublicKey: (buf) => {
			check_pub_key_length(buf);
	    return Buffer.concat([
				HOLO_HASH_AGENT_PREFIX,
				buf,
				calc_dht_bytes(buf)
	    ]);
		},
		decode: (base64) => {
			return Buffer.from(base64, "base64").slice(3,-4);
		},
		encode: (buf) => {
	    return Codec.Base64.encode(Codec.AgentId.holoHashFromPublicKey(buf));
		},
	},
	"Base36": {
		decode: (str) => base36.decode(str),
		encode: (buf) => base36.encode(Buffer.from(buf)),
	},
	"Base58":{
		decode: (str) => multihash.decode(multihash.fromB58String(str)).digest,
		encode: (buf) => multihash.toB58String(multihash.encode(Buffer.from(buf), "sha2-256")),
	},
	"Base64": {
		decode: (base64) => {
			const byteString = Buffer.from(base64, "base64").toString("binary");
			const buffer = Buffer.alloc(byteString.length);
			for(let i = 0; i < byteString.length; i++) {
					buffer[i] = byteString.charCodeAt(i);
			}
			return buffer
		},
		encode: (buf) => {
			const bytes = new Uint8Array(buf);
			const len = bytes.byteLength;
			let binary = "";
			for (let i = 0; i < len; i++) {
					binary += String.fromCharCode(bytes[i]);
			}
			const base64 = Buffer.from(binary, "binary").toString("base64");
			return base64
		},

	},
	"Signature": {
		decode: (base64) => Buffer.from(base64, "base64"),
		encode: (buf) => Codec.Base64.encode(Buffer.from(buf)),
	},
	"Digest": {
		holoHashFromBuffer: (holoHashPrefix, buf) => {
			return Buffer.concat([
				holoHashPrefix,
				buf,
				calc_dht_bytes(buf)
			]);
	},
		decodeToHoloHash:(base64) => Buffer.from(base64, "base64"),
		decode: (base64) => Buffer.from(base64, "base64").slice(3,-4),
		encode: (holoHashType, buf) => {
			const holoHashPrefix = getHoloHashPrefix(holoHashType);
			return Codec.Base64.encode(Codec.Digest.holoHashFromBuffer(holoHashPrefix, Buffer.from(buf)))
		},
	},
};

module.exports = {
    KeyManager,
    deriveSeedFrom,
    Codec,
};
