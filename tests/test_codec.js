const crypto						= require('crypto');
const expect						= require('chai').expect;

const { Codec }						= require('../src/index.js');

const sha256						= (buf) => crypto.createHash('sha256').update( Buffer.from(buf) ).digest();

describe("Codec.AgentId", () => {
	it("should get Holochain HoloHash agent ID buffer from public key buffer", () => {
		const publicKey					= new Uint8Array([
			161, 222, 128, 146, 233, 128,  11,
			197,  77,  22,   0, 199, 102, 199,
			105,  12,  19, 193,  24, 250,  79,
			198, 221, 144, 203,  23, 155, 141,
			142, 179, 124, 113
		]);
		const publicKeyBuffer            =  Buffer.from(publicKey);

		const agentId					= new Uint8Array([
			132,  32,  36, 161, 222, 128, 146, 233,
			128,  11, 197,  77,  22,   0, 199, 102,
			199, 105,  12,  19, 193,  24, 250,  79,
			198, 221, 144, 203,  23, 155, 141, 142,
			179, 124, 113, 144,  10,  68, 169
		]);
		const agentIdBuffer            =  Buffer.from(agentId);

		expect( Codec.AgentId.holoHashFromPublicKey(publicKeyBuffer)	).to.deep.equal(agentIdBuffer);
	})

	it("should decode Holochain HoloHash agent ID into public key bytes", () => {
		const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const publicKey					= new Uint8Array([
			161, 222, 128, 146, 233, 128,  11,
			197,  77,  22,   0, 199, 102, 199,
			105,  12,  19, 193,  24, 250,  79,
			198, 221, 144, 203,  23, 155, 141,
			142, 179, 124, 113
		]);

		expect( Codec.AgentId.decode(agentId)		).to.deep.equal(publicKey);
	})

	it("should encode public key bytes into Holochain HoloHash agent ID", () => {
			const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
			const publicKey					= new Uint8Array([
				161, 222, 128, 146, 233, 128,  11,
				197,  77,  22,   0, 199, 102, 199,
				105,  12,  19, 193,  24, 250,  79,
				198, 221, 144, 203,  23, 155, 141,
				142, 179, 124, 113
			]);

			expect( Codec.AgentId.encode(publicKey)		).to.equal(agentId);
	});
});

describe("Codec.Base36", () => {
	it("should decode agent ID using base36", async () => {
		const urlAgentId				= "wjzlh5yt3uk0mzpcor0i12ol0rrpxdydzggt4b2fvr8yealc";
		const publicKey					= new Uint8Array([
			1,   2,   3,   4,   5,   6,   7,
			8,   9,  10,  11,  12,  13,  14,
			15,  16,  17,  18,  19,  20,  21,
			22,  23,  24,  25,  26,  27,  28,
			29,  30,  31,  32
		]);

		expect( Codec.Base36.encode(publicKey)		).to.equal(urlAgentId);
	});

	it("should encode agent ID into base36", async () => {
		const urlAgentId				= "wjzlh5yt3uk0mzpcor0i12ol0rrpxdydzggt4b2fvr8yealc";
		const publicKey					= new Uint8Array([
			1,   2,   3,   4,   5,   6,   7,
			8,   9,  10,  11,  12,  13,  14,
			15,  16,  17,  18,  19,  20,  21,
			22,  23,  24,  25,  26,  27,  28,
			29,  30,  31,  32
		]);

		expect( Codec.Base36.encode(publicKey)		).to.equal(urlAgentId);
	});
});

describe("Codec.Base58", () => {
	it("should decode SHA-256 multihash into SHA-256 digest bytes (with base58)", async () => {
		const hashString				= "QmNZAJfVYoCASiPc3uYZXrvhRFbxJLxG18R2Ga4ZXfP4kR";
		const hashBytes					= await sha256(new Uint8Array([0xca, 0xfe]));

		expect( Codec.Base58.decode(hashString)).to.deep.equal(hashBytes);
	});

	it("should encode SHA-256 digest bytes into SHA-256 multihash (with base58)", async () => {
		const hashBytes					= await sha256(new Uint8Array([0xba, 0xbe]));
		const hashString				= "QmeTu8d5sUNULwS72NxLNTMhLZfPma4qcWvG2LqxiUz1Gf";

		expect( Codec.Base58.encode(hashBytes)).to.equal(hashString);
	});
});

describe("Codec.Base64", () => {
	it("should decode base64 string into buffer", async () => {
		const hashString				= "hCAkTFYCB48/Bx/QvKQPVSuXAV8sLHKJXrh6ZS8YVe2MdsvSgc7q";
		const dataBytes					= new Uint8Array([
			132, 32,  36,  76, 	86, 	2, 	 7,   143, 
			63,  7,   31,  208, 188,  164, 15,  85, 
			43,  151, 1,   95, 	44, 	44,  114, 137, 
			94,  184, 122, 101, 47, 	24,  85,  237,
			140, 118, 203, 210, 129, 206,  234
		]);
		const hashBuf					 = Buffer.from(dataBytes)

			expect( Codec.Base64.decode(hashString)).to.deep.equal(hashBuf);
	});

	it("should encode buffer into base64 string", async () => {
		const dataBytes					= new Uint8Array([
			132, 32,  36,  76, 	86, 	2, 	 7,   143, 
			63,  7,   31,  208, 188,  164, 15,  85, 
			43,  151, 1,   95, 	44, 	44,  114, 137, 
			94,  184, 122, 101, 47, 	24,  85,  237,
			140, 118, 203, 210, 129, 206,  234
		]);
		const hashBuf					 = Buffer.from(dataBytes)
		const hashString				= "hCAkTFYCB48/Bx/QvKQPVSuXAV8sLHKJXrh6ZS8YVe2MdsvSgc7q";

		expect( Codec.Base64.encode(hashBuf)).to.equal(hashString);
	});
});


describe("Codec.Signature", () => {
	it("should decode Signature string into message bytes", async () => {
		const messageBytes				= Buffer.from("example 1");
		const base64String				= "ZXhhbXBsZSAx";

		expect( Codec.Signature.decode(base64String)	).to.deep.equal(messageBytes)
	});

	it("should encode message bytes into Signature string", async () => {
		const base64String				= "ZXhhbXBsZSAy";
		const messageBytes				= Buffer.from("example 2");

		expect( Codec.Signature.encode(messageBytes)	).to.equal(base64String);
	});
});

describe("Codec.Digest", () => {
	it("should get holohash buffer from raw buffer", () => {
		const dataBytes					= new Uint8Array([
			88,	 43,  0,	 130,	130, 164, 145, 252,
			50,	 36,  8,	 37,	143, 125, 49,	 95,
			241, 139, 45,	 95,	183, 5,		123, 133,	
			203, 141,	250, 107,	100, 170, 165, 193
		]);
		const dataBuffer            =  Buffer.from(dataBytes);

		const holoHashBytes					= new Uint8Array([
			132, 33,  36,	 88,	43,  0,	 	130, 130,
			164, 145, 252, 50,	36,  8,   37,	 143,
			125, 49,  95,  241, 139, 45,  95,	 183,
			5,	 123, 133, 203, 141, 250, 107, 100, 
			170, 165, 193, 48,  200, 28,  230
		]);

		const holoHashBuffer            =  Buffer.from(holoHashBytes);

		const HOLO_HASH_ENTRY_PREFIX	= Buffer.from(new Uint8Array([0x84, 0x21, 0x24]).buffer);

		expect( Codec.Digest.holoHashFromBuffer(HOLO_HASH_ENTRY_PREFIX, dataBuffer)	).to.deep.equal(holoHashBuffer);
	})

	it("should decode HoloHash string into raw buffer", async () => {
		const hashString				= "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";
		const hashBytes					= new Uint8Array([
			88,	 43,  0,	 130,	130, 164, 145, 252,
			50,	 36,  8,	 37,	143, 125, 49,	 95,
			241, 139, 45,	 95,	183, 5,		123, 133,	
			203, 141,	250, 107,	100, 170, 165, 193
		]);
		const hashBuffer            =  Buffer.from(hashBytes)

		expect( Codec.Digest.decode(hashString)).to.deep.equal(hashBuffer);
	});

	it("should decode HoloHash string into HoloHash buffer", async () => {
		const hashString				= "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";
		const holoHashBytes					= new Uint8Array([
			132, 33,  36,	 88,	43,  0,	 	130, 130,
			164, 145, 252, 50,	36,  8,   37,	 143,
			125, 49,  95,  241, 139, 45,  95,	 183,
			5,	 123, 133, 203, 141, 250, 107, 100, 
			170, 165, 193, 48,  200, 28,  230
		]);

		const holoHashBuffer            =  Buffer.from(holoHashBytes);

		expect( Codec.Digest.decodeToHoloHash(hashString)).to.deep.equal(holoHashBuffer);
});

	it("should encode raw buffer into HoloHash string", async () => {
		const data					= new Uint8Array([
			88,	 43,  0,	 130,	130, 164, 145, 252,
			50,	 36,  8,	 37,	143, 125, 49,	 95,
			241, 139, 45,	 95,	183, 5,		123, 133,	
			203, 141,	250, 107,	100, 170, 165, 193
		]);

		const hashString				=  "uhCEkWCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcEwyBzm";

		expect( Codec.Digest.encode('entry', data)).to.equal(hashString);
	});
});
