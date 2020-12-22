const expect						= require('chai').expect;

const { Codec }						= require('../src/index.js');

describe("Codec.AgentId", () => {
	it("should decode HoloHash agent ID into HoloHash agent pubkey buffer", async () => {
		const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const holohashPubKey					= new Uint8Array([
			132,  32,  36, 161, 222, 128, 146, 233,
			128,  11, 197,  77,  22,   0, 199, 102,
			199, 105,  12,  19, 193,  24, 250,  79,
			198, 221, 144, 203,  23, 155, 141, 142,
			179, 124, 113, 144,  10,  68, 169
		]);
		const holohashPubKeyBuffer            =  Buffer.from(holohashPubKey);

		expect( Codec.AgentId.decodeToHoloHash(agentId)).to.deep.equal(holohashPubKeyBuffer);
	});

	it("should decode HoloHash agent ID into public key buffer", () => {
		const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const publicKey					= new Uint8Array([
			161, 222, 128, 146, 233, 128,  11,
			197,  77,  22,   0, 199, 102, 199,
			105,  12,  19, 193,  24, 250,  79,
			198, 221, 144, 203,  23, 155, 141,
			142, 179, 124, 113
		]);
		const publicKeyBuffer            =  Buffer.from(publicKey);

		expect( Codec.AgentId.decode(agentId)		).to.deep.equal(publicKeyBuffer);
	});

	it("should encode public key buffer into HoloHash agent ID", () => {
		const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const publicKey					= new Uint8Array([
			161, 222, 128, 146, 233, 128,  11,
			197,  77,  22,   0, 199, 102, 199,
			105,  12,  19, 193,  24, 250,  79,
			198, 221, 144, 203,  23, 155, 141,
			142, 179, 124, 113
		]);
		const publicKeyBuffer            =  Buffer.from(publicKey);

		expect( Codec.AgentId.encode(publicKeyBuffer)		).to.equal(agentId);
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
		const base64String				 = "hCAkTFYCB48/Bx/QvKQPVSuXAV8sLHKJXrh6ZS8YVe2MdsvSgc7q";

		expect( Codec.Base64.encode(hashBuf)).to.equal(base64String);
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

describe("Codec.HoloHash", () => {
	it("should return HoloHash base64 String from raw base64 string", async () => {
		const base64String				 = "hCAkTFYCB48/Bx/QvKQPVSuXAV8sLHKJXrh6ZS8YVe2MdsvSgc7q";
		const HHBase64String			 = "hCAkTFYCB48_Bx_QvKQPVSuXAV8sLHKJXrh6ZS8YVe2MdsvSgc7q";

		expect( Codec.HoloHash.holoHashStringFromB64(base64String)).to.equal(HHBase64String);
	});

	it("should return holohash buffer from raw buffer", () => {
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

		expect( Codec.HoloHash.holoHashFromBuffer(HOLO_HASH_ENTRY_PREFIX, dataBuffer)	).to.deep.equal(holoHashBuffer);
	});

	it("should decode HoloHash string into raw buffer", async () => {
		const hashString				= "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";
		const hashBytes					= new Uint8Array([
			88,	 43,  0,	 130,	130, 164, 145, 252,
			50,	 36,  8,	 37,	143, 125, 49,	 95,
			241, 139, 45,	 95,	183, 5,		123, 133,	
			203, 141,	250, 107,	100, 170, 165, 193
		]);
		const hashBuffer            =  Buffer.from(hashBytes)

		expect( Codec.HoloHash.decode(hashString)).to.deep.equal(hashBuffer);
	});

	it("should encode raw buffer into HoloHash string", async () => {
		const bytes					= new Uint8Array([
			88,	 43,  0,	 130,	130, 164, 145, 252,
			50,	 36,  8,	 37,	143, 125, 49,	 95,
			241, 139, 45,	 95,	183, 5,		123, 133,	
			203, 141,	250, 107,	100, 170, 165, 193
		]);

		const buffer            =  Buffer.from(bytes);

		const hashString				=  "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";

		expect( Codec.HoloHash.encode('entry', buffer)).to.equal(hashString);
	});

	it("should encode holohash buffer into HoloHash string", async () => {
		const holoHashBytes					= new Uint8Array([
			132, 33,  36,	 88,	43,  0,	 	130, 130,
			164, 145, 252, 50,	36,  8,   37,	 143,
			125, 49,  95,  241, 139, 45,  95,	 183,
			5,	 123, 133, 203, 141, 250, 107, 100, 
			170, 165, 193, 48,  200, 28,  230
		]);

		const holoHashBuffer            =  Buffer.from(holoHashBytes);

		const hashString				=  "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";

		expect( Codec.HoloHash.encode('entry', holoHashBuffer)).to.equal(hashString);
	});
});


describe("Codec.Digest", () => {
	it("should decode SHA-256 multihash into SHA-256 digest buffer", async () => {
		const hashString				=  "EnV7InN0ZXBzIjp7ImJhc2UiOjY0LCJwcm9jZXNzIjpbImRhdGEgd2lsbCBiZSBoYXNoZWQgaW50byBhIiwic2hhMjU2IG11bHRpaGFzaCB0aGVuIiwiZW5jb2RlZCJdfSwidGVzdCI6ImluZm9ybWF0aW9uIn0=";
		const hashBytes					= new Uint8Array([
			123,34,115,116,101,112,115,34,58,123,34,98,97,115,101,34,58,54,52,44,34,112,114,111,99,101,115,115,34,58,91,34,100,97,116,97,32,119,105,108,108,32,98,101,32,104,97,115,104,101,100,32,105,110,116,111,32,97,34,44,34,115,104,97,50,53,54,32,109,117,108,116,105,104,97,115,104,32,116,104,101,110,34,44,34,101,110,99,111,100,101,100,34,93,125,44,34,116,101,115,116,34,58,34,105,110,102,111,114,109,97,116,105,111,110,34,125
		]);
		const hashBuffer            =  Buffer.from(hashBytes)
		expect( Codec.Digest.decode(hashString)).to.deep.equal(hashBuffer);
	});

	it("should encode stringified data into base64 encoded SHA-256 multihash", async () => {
		const jsonData				=  {
			"test": "information",
			"steps": {
				"process": ["data will be hashed into a", "sha256 multihash then", "encoded"],
				"base": 64
			}
		};

		const hashString				=  "EnV7InN0ZXBzIjp7ImJhc2UiOjY0LCJwcm9jZXNzIjpbImRhdGEgd2lsbCBiZSBoYXNoZWQgaW50byBhIiwic2hhMjU2IG11bHRpaGFzaCB0aGVuIiwiZW5jb2RlZCJdfSwidGVzdCI6ImluZm9ybWF0aW9uIn0=";
		
		expect( Codec.Digest.encode(jsonData)).to.equal(hashString);
	});

	it("should encode sha256 digest buffer into base64 encoded SHA-256 multihash", async () => {
		const hashBytes					= new Uint8Array([
			123,34,115,116,101,112,115,34,58,123,34,98,97,115,101,34,58,54,52,44,34,112,114,111,99,101,115,115,34,58,91,34,100,97,116,97,32,119,105,108,108,32,98,101,32,104,97,115,104,101,100,32,105,110,116,111,32,97,34,44,34,115,104,97,50,53,54,32,109,117,108,116,105,104,97,115,104,32,116,104,101,110,34,44,34,101,110,99,111,100,101,100,34,93,125,44,34,116,101,115,116,34,58,34,105,110,102,111,114,109,97,116,105,111,110,34,125
		]);
		const hashBuffer            =  Buffer.from(hashBytes)
		
		const hashString				=  "EnV7InN0ZXBzIjp7ImJhc2UiOjY0LCJwcm9jZXNzIjpbImRhdGEgd2lsbCBiZSBoYXNoZWQgaW50byBhIiwic2hhMjU2IG11bHRpaGFzaCB0aGVuIiwiZW5jb2RlZCJdfSwidGVzdCI6ImluZm9ybWF0aW9uIn0=";
		
		expect( Codec.Digest.encode(hashBuffer)).to.equal(hashString);
	});
});
