## Development guidelines

See [Readme.md](Readme.md) as well.

General:
- coding style should be clean, straightforward and documented, in a similar fashion as go-ucan.
- keep the dependencies minimal, favor the standard go libraries
- code should be decently tested and profiled
- specifications and test vectors origins used MUST be referenced in a comment
- if something differs from a specification, it should be documented and explained
- consider how an average user will read and understand your code, rather than how you read it 

DIDs:
- DID and document structs are minimal/lightweight and get expanded into the relevant interface (DID, Document).
- They get expanded when marshalling into JSON but not otherwise. DID Documents are for out-of-process communication, not the normal path.

Crypto:
- a user of the library shouldn't have to know or care about the underlying crypto to use it "server side" (signature verification, key agreement). Thus, it should be abstracted behind the VerificationMethod interfaces.
- for each, we should expose some generally useful functions to handle private keys (generation, marshalling...)
