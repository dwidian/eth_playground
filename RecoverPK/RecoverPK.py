# %%
from eth_keys import keys
from eth_keys import KeyAPI
from eth_account.messages import encode_defunct
from eth_account import Account

# %% [markdown]
# Set Private Key

# %%
pk = keys.PrivateKey(b'\x01' * 32)

# %% [markdown]
# Set Message

# %%
pesan = 'Percobaan'

# %% [markdown]
# Add additional bytes according EIP-191 (https://eips.ethereum.org/EIPS/eip-191)

# %%
pesan_with_RLP = "\x19Ethereum Signed Message:\n" + str(len(pesan)) + pesan

# %% [markdown]
# # Recover PK using eth_keys

# %%
signature = pk.sign_msg(bytes(pesan_with_RLP, 'utf-8'))

# %% [markdown]
# Check if recovered PK is correct

# %%
signature.recover_public_key_from_msg(bytes(pesan_with_RLP, 'utf-8')) == pk.public_key

# %% [markdown]
# # Recover PK using KeyAPI

# %% [markdown]
# Use previous generated signature

# %%
signature = KeyAPI.Signature(bytes.fromhex(signature.to_hex()[2:]))

# %% [markdown]
# Check if recovered PK is correct

# %%
assert KeyAPI.PublicKey.recover_from_msg(bytes(pesan_with_RLP, 'utf-8'),signature) == pk.public_key

# %% [markdown]
# # Recover PK using eth-account

# %%
message = encode_defunct(text=pesan)

# %%
vrs = (hex(signature.v + 27),hex(signature.r), hex(signature.s))

# %%
assert Account.recover_message(message, vrs=vrs).lower() == pk.public_key.to_address()


