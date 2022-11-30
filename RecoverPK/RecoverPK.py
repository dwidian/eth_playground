# %%
from eth_keys import keys
from eth_keys import KeyAPI
from eth_account.messages import encode_defunct
from eth_account import Account
import os

# %% [markdown]
# Set Private Key

# %%
privateKey = os.urandom(32)
pk = keys.PrivateKey(privateKey)

# %%
print("#### KEY PAIR GENERATION ####")
print("Private Key \t\t: {}".format(hex(int.from_bytes(privateKey, "big"))))
print("Public Key Address \t: {}".format(pk.public_key.to_address()))

# %% [markdown]
# Set Message

# %%
pesan = 'Percobaan'

# %% [markdown]
# Add additional bytes according EIP-191 (https://eips.ethereum.org/EIPS/eip-191)

# %%
pesan_with_RLP = "\x19Ethereum Signed Message:\n" + str(len(pesan)) + pesan

# %%
print("\n#### MESSAGE ####")
print("Plain Message \t: {}".format(pesan))

# %% [markdown]
# # Recover PK using eth_keys

# %%
signature = pk.sign_msg(bytes(pesan_with_RLP, 'utf-8'))

# %%
print("\n#### GENERATE SIGNATURE ####")
print("r \t: {}".format(hex(signature.r)))
print("s \t: {}".format(hex(signature.s)))
print("v \t: {}".format(hex(signature.v)))

# %% [markdown]
# Check if recovered PK is correct

# %%
recoveredPK = signature.recover_public_key_from_msg(bytes(pesan_with_RLP, 'utf-8'))

# %%
print("\n#### RECOVER PK using eth_keys API ####")
print("Recovered Public Key Address \t: {}".format(recoveredPK.to_address()))
if (recoveredPK.to_address().lower() == pk.public_key.to_address()) :
    print("MATCHED")
else :
    print("NOT MATCHED")


# %% [markdown]
# # Recover PK using KeyAPI

# %% [markdown]
# Use previous generated signature

# %%
signature = KeyAPI.Signature(bytes.fromhex(signature.to_hex()[2:]))

# %% [markdown]
# Check if recovered PK is correct

# %%
recoveredPK = KeyAPI.PublicKey.recover_from_msg(bytes(pesan_with_RLP, 'utf-8'),signature)

# %%
print("\n#### RECOVER PK using KeyAPI API ####")
print("Recovered Public Key Address \t: {}".format(recoveredPK.to_address()))
if (recoveredPK.to_address().lower() == pk.public_key.to_address()) :
    print("MATCHED")
else :
    print("NOT MATCHED")

# %% [markdown]
# # Recover PK using eth-account

# %%
message = encode_defunct(text=pesan)

# %%
vrs = (hex(signature.v + 27),hex(signature.r), hex(signature.s))

# %%
recoveredPK = Account.recover_message(message, vrs=vrs)

# %%
print("\n#### RECOVER PK using eth-account API ####")
print("Recovered Public Key Address \t: {}".format(recoveredPK))
if (recoveredPK.lower() == pk.public_key.to_address()) :
    print("MATCHED")
else :
    print("NOT MATCHED")

# %%



