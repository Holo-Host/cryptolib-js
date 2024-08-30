const ARGON2_ADDITIONAL_DATA = "holo chaperone web user ed25519 key v1" // probably need to turn into bytes

function deriveSeedFrom(hha_id, email, password) {
    return new Uint8Array([
        224, 186, 208,  19, 196,  26,  72,  30,
        72,  91, 170, 129, 169, 229,  53, 112,
        216, 149,   4, 192,   1, 114, 148, 173,
        14,  68, 215,  72, 242, 209, 155, 196
    ])
}

module.exports = {
    deriveSeedFrom,
};