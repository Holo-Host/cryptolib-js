const expect						= require('chai').expect;

const { Codec }						= require('../src/index.js');

describe("Codec.AgentId", () => {
    it("should encode public key buffer into HoloHash agent ID and decode it back to a public key buffer", () => {
		const publicKeyb64 				= "od6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHE";
		const publicKeyBuffer           =  Buffer.from(publicKeyb64, "base64");
		const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
        expect( Codec.AgentId.encode(publicKeyBuffer)		).to.equal(agentId);
        expect( Codec.AgentId.decode(agentId)		).to.deep.equal(publicKeyBuffer);
    });
    
    it("should encode public key buffer into HoloHash agent ID and decode it to an agent HoloHash buffer", async () => {
        const publicKeyb64 				= "od6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHE";
        const publicKeyBuffer           =  Buffer.from(publicKeyb64, "base64");
        const agentId					= "uhCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const agentHoloHashb64			= "hCAkod6AkumAC8VNFgDHZsdpDBPBGPpPxt2QyxebjY6zfHGQCkSp";
		const holohashPubKeyBuffer      = Buffer.from(agentHoloHashb64, "base64" );

        expect( Codec.AgentId.encode(publicKeyBuffer)		).to.equal(agentId);
		expect( Codec.AgentId.decodeToHoloHash(agentId)).to.deep.equal(holohashPubKeyBuffer);
	});
});

describe("Codec.Base36", () => {
	it("should decode agent ID using base36 and then encode agent ID back into base36", async () => {
		const urlAgentId				= "wjzlh5yt3uk0mzpcor0i12ol0rrpxdydzggt4b2fvr8yealc";
		const publicKey					= Buffer.from("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "base64");

        expect( Codec.Base36.encode(publicKey)		).to.equal(urlAgentId);
        expect( Codec.Base36.encode(publicKey)		).to.equal(urlAgentId);
	});
});

describe("Codec.Signature", () => {
	it("should decode Signature string into message bytes and then encode message bytes back into Signature string", async () => {
		const messageBytes				= Buffer.from("example 1");
		const base64String				= "ZXhhbXBsZSAx";

        expect( Codec.Signature.decode(base64String)	).to.deep.equal(messageBytes);
        expect( Codec.Signature.encode(messageBytes)	).to.equal(base64String);
	});
});

describe("Codec.HoloHash", () => {

	it("should encode raw buffer into HoloHash string and then decode HoloHash string into raw buffer", async () => {
		const hashString				= "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";
		const rawBuffer            	=  Buffer.from( "WCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcE=", "base64" );

        expect( Codec.HoloHash.encode('entry', rawBuffer)).to.equal(hashString);
		expect( Codec.HoloHash.decode(hashString)).to.deep.equal(rawBuffer);
	});

    it("should encode holohash buffer into HoloHash string and then decode HoloHash string into raw buffer", async () => {
        const holoHashBuffer   			= Buffer.from("hCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm", "base64");
        const hashString				=  "uhCEkWCsAgoKkkfwyJAglj30xX_GLLV-3BXuFy436a2SqpcEwyBzm";
        const rawBuffer            	=  Buffer.from( "WCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcE=", "base64" );

        expect( Codec.HoloHash.encode('entry', holoHashBuffer)).to.equal(hashString);
        expect( Codec.HoloHash.decode(hashString)).to.deep.equal(rawBuffer);
    });

    it("should return holohash buffer from raw buffer", () => {
		const dataBuffer            	=  Buffer.from("WCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcE=", "base64");
		const holoHashBuffer            =  Buffer.from("hCEkWCsAgoKkkfwyJAglj30xX/GLLV+3BXuFy436a2SqpcEwyBzm", "base64");

		expect( Codec.HoloHash.holoHashFromBuffer('entry', dataBuffer)	).to.deep.equal(holoHashBuffer);
	});
});

describe("Codec.Digest", () => {
	it("should encode sha256 digest buffer into base64 encoded SHA-256 multihash and then decode SHA-256 multihash into SHA-256 digest buffer", async () => {
		const hashDigest				= "eyJzdGVwcyI6eyJiYXNlIjo2NCwicHJvY2VzcyI6WyJkYXRhIHdpbGwgYmUgaGFzaGVkIGludG8gYSIsInNoYTI1NiBtdWx0aWhhc2ggdGhlbiIsImVuY29kZWQiXX0sInRlc3QiOiJpbmZvcm1hdGlvbiJ9";
		const digestBuffer            	=  Buffer.from(hashDigest, "base64");
		const hashString				=  "EnV7InN0ZXBzIjp7ImJhc2UiOjY0LCJwcm9jZXNzIjpbImRhdGEgd2lsbCBiZSBoYXNoZWQgaW50byBhIiwic2hhMjU2IG11bHRpaGFzaCB0aGVuIiwiZW5jb2RlZCJdfSwidGVzdCI6ImluZm9ybWF0aW9uIn0=";
        expect( Codec.Digest.encode(digestBuffer)).to.equal(hashString);
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
});
