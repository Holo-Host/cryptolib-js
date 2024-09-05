const expect = require('chai').expect
const crypto = require('crypto')

const { KeyManager, deriveSeedFrom } = require('../src/index.js')

const wait = ms => new Promise(resolve => setTimeout(resolve, ms))

const hha_id = new Uint8Array([
    66, 123, 133, 136, 133,   6, 247, 116,
     4,  59,  43, 206, 131, 168, 123,  44,
    54,  52,   3,  53, 134,  75, 137,  43,
    63,  26, 216, 191,  67, 117,  38, 142
])

describe("Key Manager", () => {
    it("should create KeyManager instance with random bytes", async () => {
        const seed = crypto.randomBytes( 32 )
        const keys = new KeyManager( seed )

        await wait(100) // wait for pubkey to load

        expect( keys.publicKey() ).to.be.a("uint8array")
    })

    it("should derive seed from input", async () => {
        const expectedSeed = new Uint8Array([
            225, 186, 208,  19, 196,  26,  72,  30,
            72,  91, 170, 129, 169, 229,  53, 112,
            216, 149,   4, 192,   1, 114, 148, 173,
            14,  68, 215,  72, 242, 209, 155, 196
        ])

        const seed = deriveSeedFrom(hha_id, "example@holo.host", "password")

        expect( seed ).to.be.an("uint8array")
        expect( seed ).to.deep.equal( expectedSeed )
    })

    it("should sign and verify using derived seed", async () => {
        const expectedPubkey = new Uint8Array([
            253, 163, 6, 143, 70, 91, 132, 195, 
            250, 73, 221, 250, 186, 8, 83, 172, 
            77, 56, 95, 189, 150, 20, 188, 161, 
            40, 226, 241, 43, 45, 119, 221, 134,         
        ])

        const expectedSignature = new Uint8Array([
            121, 105, 219, 165, 125, 230, 134, 244, 134, 164, 10, 240, 125, 89, 255, 226, 115, 5, 130, 19, 184, 226, 212, 2, 104, 13, 217, 222, 84, 54, 80, 103, 205, 34, 46, 215, 30, 68, 130, 60, 147, 207, 7, 46, 54, 238, 19, 255, 28, 209, 186, 5, 247, 198, 204, 84, 189, 233, 90, 230, 65, 24, 67, 5 
        ])
 
        const seed = deriveSeedFrom(hha_id, "example2@holo.host", "password")
        const keys = new KeyManager( seed )

        await wait(100) // wait for pubkey to load

        expect ( keys.publicKey() ).to.deep.equal(expectedPubkey)

        const message = "Hello, world!"

        const signature = keys.sign( message )

        expect( signature ).to.be.an("uint8array")
        expect( signature ).to.deep.equal( expectedSignature )

        const isGenuine = keys.verify( message, signature )

        expect( isGenuine ).to.be.true

        const isGenuineStatic = KeyManager.verifyWithPublicKey( message, signature, keys.publicKey() )

        expect( isGenuineStatic ).to.be.true
    })
})
