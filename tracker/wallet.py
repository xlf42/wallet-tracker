"""Example of keys derivation using BIP84."""

import sys

from typing import Dict, Optional

from bip_utils.utils.mnemonic import Mnemonic  # type:ignore
from bip_utils import (  # type:ignore
    Bip39SeedGenerator,
    Bip44Changes,
    Bip84,
    Bip84Coins,
)


class Bip84Wallet:
    """
    A Class handling a Bip84 wallet.
    """

    def __init__(self, mnemo_string: Optional[str] = None):
        """
        Initialize a Wallet from the mnemonic string
        """
        self._mnemonic = Mnemonic.FromString(mnemo_string)
        self._seed_bytes = Bip39SeedGenerator(self._mnemonic).Generate()
        self._master_key = Bip84.FromSeed(self._seed_bytes, Bip84Coins.BITCOIN)
        self.create_account()
        self.create_bip32_keys()

    def private_key_hex(self) -> str:
        """
        Generate the masterkey as a hex string
        """
        return self._master_key.PrivateKey().Raw().ToHex()

    def private_key_extended(self) -> str:
        """
        Generate the masterkey as an extended key string
        """
        return self._master_key.PrivateKey().ToExtended()

    def private_key_wif(self) -> str:
        """
        Generate the masterkey in WIF
        """
        return self._master_key.PrivateKey().ToWif()

    def public_key_extended(self) -> str:
        """
        Generate the masterkey as an extended key string
        """
        return self._master_key.PublicKey().ToExtended()

    def create_account(self):
        """
        Derive an account key pair from the master key
        """
        self._account = self._master_key.Purpose().Coin().Account(0)

    def account_private_key_extended(self) -> str:
        """
        Generate the private account key as an extended key string
        """
        return self._account.PrivateKey().ToExtended()

    def account_public_key_extended(self) -> str:
        """
        Generate the public account key as an extended key string
        """
        return self._account.PublicKey().ToExtended()

    def create_bip32_keys(self):
        """
        Derive a BIP32 key pair
        """
        self._bip32_keys = self._account.Change(Bip44Changes.CHAIN_EXT)

    def bip32_private_key_extended(self) -> str:
        """
        Generate the BIP32 extended private key
        """
        return self._bip32_keys.PrivateKey().ToExtended()

    def bip32_public_key_extended(self) -> str:
        """
        Generate the BIP32 extended private key
        """
        return self._bip32_keys.PublicKey().ToExtended()

    def bip32_keypairs(self, keypair_range: range) -> Dict[int, Dict[str, str]]:
        """
        return a list of public addresses accoording to the configured
        derivation and given range
        """
        ret_val: Dict[int, Dict[str, str]] = {}
        for i in keypair_range:
            key_pair = self._bip32_keys.AddressIndex(i)
            ret_val[i] = {}
            ret_val[i]["private_key"] = key_pair.PrivateKey().ToWif()
            ret_val[i]["public_key"] = key_pair.PublicKey().ToExtended()
        return ret_val

    def bip32_addresses(self, address_range: range) -> Dict[int, str]:
        """
        return a list of public addresses accoording to the configured
        derivation and given range
        """
        ret_val: Dict[int, str] = {}
        for i in address_range:
            key_pair = self._bip32_keys.AddressIndex(i)
            ret_val[i] = key_pair.PublicKey().ToAddress()
        return ret_val


if __name__ == "__main__":
    # pylint: disable=invalid-name
    mnemonic = (
        "jar deposit ridge ceiling come muffin hotel season weird crater fork rubber"
    )
    # pylint: enable=invalid-name
    wallet = Bip84Wallet(mnemonic)
    # Print master key
    print(f"Master key (bytes): {wallet.private_key_hex()}")
    print(f"Master key (extended): {wallet.private_key_extended()}")
    print(f"Master key (WIF): {wallet.private_key_wif()}")
    print(f"Public key (extended): {wallet.public_key_extended()}")
    print(f"Account Private key (extended): {wallet.account_private_key_extended()}")
    print(f"Account Public key (extended): {wallet.account_public_key_extended()}")
    print(f"BIP32 Private key (extended): {wallet.bip32_private_key_extended()}")
    print(f"BIP32 Public key (extended): {wallet.bip32_public_key_extended()}")
    print(f"First 5 addresses: {wallet.bip32_addresses(range(5))}")
    print(f"First 5 keypairs: {wallet.bip32_keypairs(range(5))}")

    sys.exit(0)
