# SilverLock

SilverLock is a really, really simple and practical file protector.
Use it on any file:

`silverlock myfile.txt`

Enter your password, and done. It's protected.

Need the contents back?

`silverlock myfile.agl`

Type your password once again, and poof. Your file comes back from the very depths of ~~hell~~ entropy.

## Why?

I needed to store some SSH keys remotely, so better protecting them with something only I know (dubious argument at best, but eh). I also took the opportunity to write crypto code using safe primitives and get it working, for what it's worth. Rest assured, I am not bollocks enough to [roll my own crypto](https://vnhacker.blogspot.com/2020/08/so-you-want-to-roll-your-own-crypto.html).

## Usage

SilverLock is capable of encrypting several files at once with the same password. This is perfectly secure, as the underlying keys used to actually encrypt each file are different (keys are derived from the password using a KDF with a random salt). To encrypt multiple files at once, run:

`silverlock file1 file2 file3...`

SilverLock internally stores the original file name and extension in the newly protected files, named after the original but stripped from their old extension, so SilverLock can replace them with its own extension (.agl). You may also rename them to lessen recognizability by third parties. To decrypt multiple files at once, that you *know* were protected using the **SAME** password, run:

`silverlock file1.agl file2.agl file3.agl...`

**NOTE**: After any operation on a file, SilverLock will shred and remove the original file. Use the `-k` or `--keep` option to disable this behaviour.

## Dependencies

SilverLock uses CMake to compile, and makes good use of the wonderful [libsodium](https://github.com/jedisct1/libsodium) library to perform actual crypto.

SilverLock also comes with its own copy of [CLI11](https://github.com/CLIUtils/CLI11), used to parse command line arguments.

## Details

- Key derivation is performed by a memory-hard algorithm, with a randomly generated salt so password reuse is safe (something something Argon2i)
- Additional data (like original file name, and salt used to generate the key) are stored at the beginning of the protected file, along with its own keyed hash to check for malicious modifications (something something Blake2b)
- Actual file data are encrypted with an authenticated stream cipher (something something XChaCha20 stream cipher with Poly1305 authentication)

## ! DISCLAIMER !

There actually *exists* a vulnerability in this code, that may allow some really nasty things to happen if not patched. Can you find it?

Never trust any file obtained from unknown sources.

No need to open an issue and tell me about it. This was done on purpose (well, more like I discovered it, then thought it would be cool to keep the vuln in for some reason).
