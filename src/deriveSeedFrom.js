
const { sha512 } = require("js-sha512")
const argon2 = require("argon2-browser")

const ARGON2_ADDITIONAL_DATA = "holo chaperone web user ed25519 key v1" // probably need to turn into bytes

function deriveSeedFrom(hha_id, email, password) {
    throw new Error("javascript deriveSeedFrom is not implemented yet")

    // return new Uint8Array([
    //     224, 186, 208,  19, 196,  26,  72,  30,
    //     72,  91, 170, 129, 169, 229,  53, 112,
    //     216, 149,   4, 192,   1, 114, 148, 173,
    //     14,  68, 215,  72, 242, 209, 155, 196
    // ])

    let salt = sha512.digest(email)

    // const seed = argon2.hash({
    //     pass: password,
    //     salt,
    //     type: argon2.ArgonType.Argon2id
    // })

    // {
    //  // optional
    //  time: 1, // the number of iterations
    //  mem: 1024, // used memory, in KiB
    //  hashLen: 24, // desired hash length
    //  parallelism: 1, // desired parallelism (it won't be computed in parallel, however)
    //  secret: new Uint8Array([...]), // optional secret data <- hha_id
    //  ad: new Uint8Array([...]), // optional associated data
    // }

    console.log("^&* seed", seed)

    return seed
}

module.exports = {
    deriveSeedFrom,
};