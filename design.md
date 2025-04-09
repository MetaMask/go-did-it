## Development guidelines

See [Readme.md](Readme.md) as well.

General:
- coding style should be clean, straightforward and documented, in a similar fashion as go-ucan.
- keep the dependencies minimal, favor the standard go libraries
- code should be decently tested and profiled
- specifications and test vectors used MUST be referenced in a comment
- if something differs from a specification, it should be documented and explained
- generally, follow the existing structure of did:key, ed25519 or x25519
- consider how an average user will read and understand your code, rather than how you read it 

DIDs:
- DID and document structs are minimal/lightweight and get expanded into the relevant interface (DID, Document).
- They get flattened when marshalling into JSON but not otherwise. DID Documents are for out-of-process communication, not the normal path.
- this library should also have a generic Document struct, to accept arbitrary DID documents in JSON format 

Crypto:
- each type of crypto handling should be self-contained in the relevant verification method package (e.g. everything ed25519 is in /verifications/ed25519). This includes the JSON (un)marshalling of the VerificationMethod.
- a user of the library shouldn't have to know or care about the underlying crypto to use it "server side" (signature verification, key agreement). Thus, it should be abstracted behind the VerificationMethod interfaces.
- for the same reason, each of those packages should expose or alias the relevant types (ex: PublicKey/PrivateKey in /verifications/ed25519) to expose a regular way to work with crypto primitives, as well as allowing behind the scene upgrades.
- for each, we should expose some generally useful functions to handle private keys (generation, marshalling...)

## Minimal target features

Methods:
- did:key
- did:pkh

Verification Methods:
- ed25519
- x25519
- secp256k1
- p256
- p384