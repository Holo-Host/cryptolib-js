const { KeyManager,
	deriveSeedFrom }		= require("@holo-host/wasm-key-manager");
const blake				= require("blakejs");
const multihash				= require("multihashes");
const SerializeJSON				= require("json-stable-stringify");
const base36				= require("base-x")("0123456789abcdefghijklmnopqrstuvwxyz");

const HOLO_HASH_AGENT_PREFIX		= Buffer.from(new Uint8Array([0x84, 0x20, 0x24]).buffer);
const HOLO_HASH_HEADER_PREFIX		= Buffer.from(new Uint8Array([0x84, 0x29, 0x24]).buffer);
const HOLO_HASH_ENTRY_PREFIX		= Buffer.from(new Uint8Array([0x84, 0x21, 0x24]).buffer);
const HOLO_HASH_DNA_PREFIX		  = Buffer.from(new Uint8Array([0x84, 0x2d, 0x24]).buffer);

const getHoloHashPrefix = holoHashType => {
	let holoHashPrefix;
	switch (holoHashType) {
		case "agent":
			holoHashPrefix = HOLO_HASH_AGENT_PREFIX;
			break;
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

function check_holohash_pub_key_length (pubkey) {
	if (Buffer.byteLength(pubkey) !== 39)
		throw new Error(`Unexpected pubkey length of ${Buffer.byteLength(pubkey)}.  Should be 39 bytes`);
	return pubkey;
}

function convert_b64_to_holohash_b64 (rawBase64) {
	let holoHashbase64 = '';
	const len = rawBase64.length;
	for (let i = 0; i < len; i++) {
		let char = rawBase64[i];
		if (char === '/') {
			char = '_'
		} else if (char === '+') {
			char = '-'
		}
		holoHashbase64 += char;
	}
	return holoHashbase64;
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
		decode: (base64) => Codec.HoloHash.decode(base64),
		encode: (buf) => {
		check_pub_key_length(Buffer.from(buf));
		return Codec.Base64.encodeToHoloHashB64(Codec.HoloHash.encode("agent", Buffer.from(buf)));
		},
		decodeToHoloHash:(base64) => {
		return Buffer.from(base64.slice(1), "base64");
		},
		encodeFromHoloHash: (buf) => {
		check_holohash_pub_key_length(buf);
		return "u" + Codec.Base64.encodeToHoloHashB64(buf);
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
			const base64 = buf.toString("base64");
			return base64
		},
		base64ToHoloHashB64: (base64) => {
			const HHBase64 = convert_b64_to_holohash_b64(base64);
			return HHBase64
		},
		encodeToHoloHashB64: (buf) => {
			const rawBase64 = buf.toString("base64");
			const HHBase64 = convert_b64_to_holohash_b64(rawBase64);
			return HHBase64;
		},

	},
	"HoloHash": {
		holoHashFromBuffer: (holoHashPrefix, buf) => {
			return Buffer.concat([
				holoHashPrefix,
				buf,
				calc_dht_bytes(buf)
			]);
		},
		decode: (base64) => Buffer.from(base64.slice(1), "base64").slice(3,-4),
		encode: (holoHashType, buf) => {
			const holoHashPrefix = getHoloHashPrefix(holoHashType);
			return "u" + Codec.Base64.encodeToHoloHashB64(Codec.HoloHash.holoHashFromBuffer(holoHashPrefix, Buffer.from(buf)))
		}
	},
	"Signature": {
		decode: (base64) => Buffer.from(base64, "base64"),
		encode: (buf) => Codec.Base64.encode(Buffer.from(buf)),
	},
	"Digest": {
		decode: (base64) => Codec.HoloHash.decode(base64),
		encode: (data) => {
			const buf = Buffer.from( typeof data === "string" ? data : SerializeJSON( data ) )
			const sha256 = multihash.encode(buf, "sha2-512");
			return Codec.HoloHash.encode('entry', Buffer.from(sha256))
		},
		decodeToHoloHash:(base64) => Buffer.from(base64.slice(1), "base64"),
	},
};

module.exports = {
    KeyManager,
    deriveSeedFrom,
    Codec,
};
