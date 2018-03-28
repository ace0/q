"""
Q: a python library and command-line tool for managing a quorum of hardware 
devices (Yubikeys) required to unlock a secret.
"""
from base64 import (
  urlsafe_b64encode as b64enc, 
  urlsafe_b64decode as b64dec)
from subprocess import PIPE, STDOUT
from secrets import token_bytes as randomBytes
from time import sleep
from collections import namedtuple
import subprocess

from Crypto.Hash import SHA256
import gfshare
import fire

secretShareEntry = namedtuple("secretShareEntry", "coeff encryptedShare")

class Cli:
  """
  Command line interface to Q.
  """
  def __init__(self):
    pass

  def split(self, k, n, length=128, pubkeydir="./", 
    out="./secrete-bundle.json"):
    """
    Generate a new secret and split it into shares.
    """
    k, n = int(k), int(n)
    shares = Crypto.splitSecret(bits=length, k=k, n=n)

    # Maps pubkey fingerprint => (coefficient, encryptedShare)
    bundle = {}

    # Encrypt each share.

  def genkey(pubkeyfile):
    err = Crypto.genPubkeyPair(pubkeyfile)
    if err:
      print(f"ERROR: {err}")

  def encrypt(self, pubkeyfile, ctxtfile):
    err = Crypto.encrypt(
      plaintext="hello, world", 
      pubkeyfile=pubkeyfile, 
      ctxtfile=ctxtfile)
    if err:
      print(f"ERROR: {err}")

  def decrypt(self, ctxtfile):
    ok, result = Crypto.decrypt(ctxtfile)
    if ok:
      print(f"Recovered: '{result}'")
    else:
      print(f"ERROR: {result}")

class Crypto:
  """
  Interface to crypto operations.
  """
  # We're using the 9c slot on Yubico device to store privkeys.
  # This is not a requirement, just our convention.
  # In the pkcs15-tool, this is designated key 3
  YUBICO_PRIVKEY_SLOT = "9c"
  PKCS15_KEY_NUMBER = "3"

  def __init__(self):
    pass

  def splitSecret(bits=128, k=3, n=5):
    """
    Generate a new secret and split into shares
    """
    if k > n:
      raise ValueError(f"Quorum K cannot be larger than total number "
        "of shares N. Instead found K={k} and N={n}")

    secret = randomBytes(nbytes=int(bits/8))
    return gfshare.split(k, n, bytes(secret))

  def genPubkeyPair(pubkeyfile):
    """
    Generates a new pubkey pair on a Yubico device using the 
    yubico-piv-tool command (called via subprocess). Privkey is
    stored on the device and pubkey is written to pubkeyfile.
    """
    # TODO: Change these to long form for ease of maintenance
    result = subprocess.run(
      ["yubico-piv-tool",
        "-a", "generate",
        "-s", Crypto.YUBICO_PRIVKEY_SLOT],
        stdout=PIPE
        )

    if result.returncode != 0:
      return result.stderr.encode("utf-8")

    # Write the pubkey to a file
    with open(pubkeyfile, "wb") as out:
      out.write(result.stdout)

    return None

  def encrypt(plaintext, pubkeyfile, ctxtfile):
    """
    Encrypts (using OpenSSL called via subprocess) the plaintext 
    using a pubkey read from a file. The resulting ciphertext is 
    written to ctxfile.
    """
    _, err = runWithStdin(
      cmd=["openssl", 
        "pkeyutl", "-encrypt",
        "-pubin",
        "-inkey", pubkeyfile,
        "-out", ctxtfile,
      ], 
      input=plaintext)
    return err

  def decrypt(ctxtfile, pin="123456"):
    return run(
      ["pkcs15-crypt",
        "--decipher", 
        "-i", ctxtfile,
        "t", "-o", "/dev/stdout", 
        "--pkcs1", 
        "-p", pin, 
        "--key", Crypto.PKCS15_KEY_NUMBER
      ])

  def fingerprint(data):
    """
    Generates base64 encoded fingerprint using SHA256. 
    Particularly useful for identifying pubkeys.
    """
    return SHA256.new(data=pubkey.exportKey(format='PEM')).digest()

def run(cmd):
  """
  Runs @cmd and captures stdout and stderr.
  """
  result = subprocess.run(cmd, stdout=PIPE)
  output =result.stdout.decode("utf-8")
  return (result.returncode == 0, output)

def _runWithStdin(cmd, input):
  """
  Runs @cmd, passes the string @input to the process, and 
  returns stdout or any errors.
  @returns (ok, output)
  """
  proc = subprocess.Popen(
    cmd, 
    stdin=PIPE,
    stdout=PIPE, 
    stderr=STDOUT)

  # Write the plaintext to STDIN
  proc.stdin.write(input.encode("utf-8"))
  proc.stdin.close()

  # Wait for openssl to finish
  while proc.returncode is None:
    proc.poll()
    sleep(1)

  output = proc.stdout.read().decode('utf-8')
  proc.stdout.close()

  return (proc.returncode == 0, output)

usage = \
"""
q COMMAND [OPTIONS]
Manage a quorum of hardware devices (Yubikeys) used to protect a secret.

COMMANDS

q enroll
Enroll a new device; set the PIN; and generate a pubkey pair.

q split K N [--length BITS] [--pubkeydir DIR] [--out PATH]
Generate and split a new random secret and encrypt each share using public
keys.

K          K (decrypted) shares represents a quorom and can be used to recover 
            the secret (2 or 3 is a common setting).
N          N shares are created (N must be larger or equal to K).
keysize    The size of the new secret in bits; default=128.
pubkeydir  Public keys for encrypting the keyshares are found in this 
            directory; default=./
output     Write the encrypted bundle of shares to this location; 
            default=./quorum-secret

q recover BUNDLE [--out PATH] [--print]
Recover a secret from the encrypted bundle. Prompt for individual 
hardware devices to be inserted.

BUNDLE    The bundle of encrypted shares
out       Write the output here; default is a temp file and path is printed
           to STDERR.
print     Print the recovered secret to STDOUT and don't write the output to
           a file.

q resplit BUNDLE K N [--pubkeydir DIR [--out PATH]
Recover and then re-split and re-encrypt a secret.
"""
# TODO: Establish PIN policy. 
# Maybe: gen during pubkey creation and store alongside pubkeys.
# Set mngmt key, PUK, and PIN

# Run!
if __name__ == '__main__':
  fire.Fire(Cli)
