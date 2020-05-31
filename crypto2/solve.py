#!/usr/bin/env python3
from sage.all import *
from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import RSA

message = 6213639477312598145146606285597413094756028916460209994926376562685721597532354994527411261035070313371565996179096901618661905020103824302567694878011247857685359643790779936360396061892681963343509949795893998949164356297380564973147847768251471545846793414196863838506235390508670540548621210855302903513284961283614161501466772253041178512706947379642827461605012461899803919210999488026352375214758873859352222530502137358426056819293786590877544792321648180554981415658300194184367096348141488594780860400420776664995973439686986538967952922269183014996803258574382869102287844486447643771783747439478831567060
pubkey = RSA.importKey("""
-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBXyI8cm57UfYRPh7KfRHlu
F85Hwv4kzBq340QyszUhJGPSOZ0HRxGABXLqaBLikBICvF8ZDMtJZtVwkEpBaXpj
ZEiK4UCxtjV/xqa0rM1RenQDu8mW39ByiV9qmh6o8qbatp2hVXUXf0zvGtuQglu9
T+xQAarAGnDooQ4QEzRxOTK+R9GgnXDTEVf+JuVTd0+NnlAgmEcryocHkx4rycuS
qslEUb5vHlWLk6hoXOmE9IQK+vjSqK0NRlRUYqkYFRpQ3qGij03x5eaZsAUtpSMF
nrIdVrZ8keVqt181vJ9km+p2oTaxcNOmdvUUuciVXq94qQut1Uhbun8SF4sfj+/v
AgMBAAE=
-----END PUBLIC KEY-----
""".strip())
print(pubkey.n)
