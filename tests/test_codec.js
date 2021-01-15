const expect						= require('chai').expect;

const { Codec }						= require('../src/index.js');

describe("Codec.AgentId", () => {
	it("should decode HoloHash agent ID into HoloHash agent pubkey buffer", async () => {
		const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const agentHoloHashb64			= "hCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const holohashPubKeyBuffer            = Buffer.from(agentHoloHashb64, "base64" );

		expect( Codec.AgentId.decodeToHoloHash(agentId)).to.deep.equal(holohashPubKeyBuffer);
	});

	it("should decode HoloHash agent ID into public key buffer", () => {
		const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const publicKeyb64 				= "od6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHE";
		const publicKeyBuffer           =  Buffer.from(publicKeyb64, "base64");

		expect( Codec.AgentId.decode(agentId)		).to.deep.equal(publicKeyBuffer);
	});

	it("should encode public key buffer into HoloHash agent ID", () => {
		const publicKeyb64 				= "od6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHE";
		const publicKeyBuffer           =  Buffer.from(publicKeyb64, "base64");
		const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		expect( Codec.AgentId.encode(publicKeyBuffer)		).to.equal(agentId);
	});
});

describe("Codec.Base36", () => {
	it("should decode agent ID using base36", async () => {
		const urlAgentId				= "wjzlh5yt3uk0mzpcor0i12ol0rrpxdydzggt4b2fvr8yealc";
		const publicKey					= Buffer.from("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "base64");

		expect( Codec.Base36.encode(publicKey)		).to.equal(urlAgentId);
	});

	it("should encode agent ID into base36", async () => {
		const publicKey					= Buffer.from("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "base64");
		const urlAgentId				= "wjzlh5yt3uk0mzpcor0i12ol0rrpxdydzggt4b2fvr8yealc";

		expect( Codec.Base36.encode(publicKey)		).to.equal(urlAgentId);
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
		const dataBuffer            	=  Buffer.from("WCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcE=", "base64");
		const holoHashBuffer            =  Buffer.from("hCEkWCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcEwyBzm", "base64");

		expect( Codec.HoloHash.holoHashFromBuffer('entry', dataBuffer)	).to.deep.equal(holoHashBuffer);
	});

	it("should decode HoloHash string into raw buffer", async () => {
		const hashString				= "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";
		const hashBuffer            	=  Buffer.from( "WCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcE=", "base64" );

		expect( Codec.HoloHash.decode(hashString)).to.deep.equal(hashBuffer);
	});

	it("should encode raw buffer into HoloHash string", async () => {
		const rawBuffer 				= Buffer.from("WCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcE=", "base64");
		const hashString				=  "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";

		expect( Codec.HoloHash.encode('entry', rawBuffer)).to.equal(hashString);
	});

	it("should encode holohash buffer into HoloHash string", async () => {
		const holoHashBuffer   			= Buffer.from("hCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm", "base64");
		const hashString				=  "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";

		expect( Codec.HoloHash.encode('entry', holoHashBuffer)).to.equal(hashString);
	});
});

describe("Codec.Digest", () => {
	it("should decode SHA-256 multihash into SHA-256 digest buffer", async () => {
		const hashString				=  "EnV7InN0ZXBzIjp7ImJhc2UiOjY0LCJwcm9jZXNzIjpbImRhdGEgd2lsbCBiZSBoYXNoZWQgaW50byBhIiwic2hhMjU2IG11bHRpaGFzaCB0aGVuIiwiZW5jb2RlZCJdfSwidGVzdCI6ImluZm9ybWF0aW9uIn0=";
		const hashDigest				= "eyJzdGVwcyI6eyJiYXNlIjo2NCwicHJvY2VzcyI6WyJkYXRhIHdpbGwgYmUgaGFzaGVkIGludG8gYSIsInNoYTI1NiBtdWx0aWhhc2ggdGhlbiIsImVuY29kZWQiXX0sInRlc3QiOiJpbmZvcm1hdGlvbiJ9";
		const digestBuffer            	=  Buffer.from(hashDigest, "base64");
		expect( Codec.Digest.decode(hashString)).to.deep.equal(digestBuffer);
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
		const hashDigest					= "eyJzdGVwcyI6eyJiYXNlIjo2NCwicHJvY2VzcyI6WyJkYXRhIHdpbGwgYmUgaGFzaGVkIGludG8gYSIsInNoYTI1NiBtdWx0aWhhc2ggdGhlbiIsImVuY29kZWQiXX0sInRlc3QiOiJpbmZvcm1hdGlvbiJ9";
		const digestBuffer           	 	=  Buffer.from(hashDigest, "base64");
		const hashString					=  "EnV7InN0ZXBzIjp7ImJhc2UiOjY0LCJwcm9jZXNzIjpbImRhdGEgd2lsbCBiZSBoYXNoZWQgaW50byBhIiwic2hhMjU2IG11bHRpaGFzaCB0aGVuIiwiZW5jb2RlZCJdfSwidGVzdCI6ImluZm9ybWF0aW9uIn0=";
		
		expect( Codec.Digest.encode(digestBuffer)).to.equal(hashString);
	});
});
