#!/usr/bin/env python3
import base64,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,PublicFormat,NoEncryption
out=Path(sys.argv[1] if len(sys.argv)>1 else '.')
out.mkdir(parents=True,exist_ok=True)
priv=Ed25519PrivateKey.generate(); pub=priv.public_key()
(out/'notary_private.pem').write_bytes(priv.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
(out/'notary_private.pem').chmod(0o600)
(out/'notary_public.b64').write_text(base64.b64encode(pub.public_bytes(Encoding.Raw,PublicFormat.Raw)).decode()+"\n")
print(out/'notary_public.b64')
