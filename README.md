# SilverLock

SilverLock is a really, really simple and practical file protector.
Use it on any file:

`silverlock myfile.txt`

Hit your password, and done. It's protected.

Need the contents back?

`silverlock myfile.agl`

Hit your password once again, and poof. Chest open, you're rich.

## Why?

I needed to store some SSH keys remotely, so better protecting them with something only I know. I also took the opportunity to write some basic crypto code and see it work, for what it's worth.

## Usage

SilverLock is capable of encrypting several files in a row with the same password. This is perfectly secure, as the underlying key used to actually encrypt the files are different. To encrypt multiple files at once, run:

`silverlock file1 file2 file3...`

SilverLock internally store the original file names and extensions in the newly protected files, named after the original but stripped from their old extension, so SilverLock can replace them with its own extension (.agl). You may also rename them to lessen recognizability by other parties. To decrypt multiple files at once, that you *know* were protected with the **SAME** password, run:

`silverlock file1.agl file2.agl file3.agl...`

**NOTE**: After any operation with a file, SilverLock will shred and remove the original file. Use the `-k` or `--keep` option to disable this behaviour.

## Dependencies

SilverLock uses CMake to compile, makes good use of the wonderful [https://github.com/jedisect1/libsodium](libsodium) library to perform actual crypto.

SilverLock also comes with its own copy of [https://github.com/CLIUtils/CLI11](CLI11), used to parse command line arguments.

## Details

- Key derivation is performed by a memory-hard algorithm, with a randomly generated salt (something something Argon2i)
- Less sensible data (like original file name, and salt used to generate the key) is stored at the beginning of the protected file, along with a keyed hash to check for malicious modifications of these data (something something Blake2b)
- Actual file data is encrypted with a salted authenticated stream cipher (something something XChaCha20 stream cipher with Poly1305 authentication)

## ! DISCLAIMER !

There *is* actually a vulnerability in this code, that may allow some really nasty things to happen if not patched. Can you find it?

Never trust any file obtained from unknown sources.

So, no need to open an issue to tell me about it. This is **on purpose**.
