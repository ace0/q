"""
Q: a python library and command-line tool for managing a quorum of hardware 
devices (Yubikeys) required to unlock a secret.
"""
from base64 import urlsafe_b64encode, urlsafe_b64decode
from collections import namedtuple
from glob import glob
from hashlib import sha256
from json import dumps as jsonEnc, loads as jsonDec
from subprocess import PIPE, STDOUT
from secrets import token_bytes as randomBytes
from time import sleep

import subprocess

import gfshare, fire

secretShareEntry = namedtuple("secretShareEntry", "coeff encryptedShareFile")
MANIFEST = "manifest.json"

class Cli:
  """
  Command line interface to Q.
  """
  def __init__(self):
    pass

  def split(self, k, n, length=128, pubkeydir=".", outdir="./bundle"):
    """
    Generate a new secret, split it into shares, encrypt them, and write 
    them in a bundle to a file.
    """
    # TODO: Add extension option, ext=.pubkey
    # Verify cmd line arguments
    k, n = int(k), int(n)
    pubkeyfiles = glob(f"{pubkeydir}/*.pubkey")
    if n != len(pubkeyfiles):
      print(f"ERROR: The total number of shares, N, must match the number of "
        "pubkey files. Instead found N={n}, number of pubkeyfiles="
        "{len(pubkeyfiles)}")
      exit(1)

    shares = Crypto.splitSecret(bits=length, k=k, n=n)

    # Maps pubkey fingerprint => (coefficient, encryptedShare)
    manifest = { "K": k, "N": n}

    # LEFT OFF: Implementing encryption of individual shares
    # Encrypt each share under a distinct pubkey
    for (pkfile, (coeff, share)) in zip(pubkeyfiles, shares.items()):
      print(f"{pkfile} {coeff} {share}")

      # Encrypt the share and write it to a file
      sharefile = f"share-{coeff}.ctxt"
      Crypto.encrypt(
        plaintext=share,
        pubkeyfile=pkfile, 
        ctxtfile=f"{outdir}/{sharefile}")

      # Stores these detes into the manifest
      fp = Crypto.fingerprintFile(pkfile)
      manifest[fp] = secretShareEntry(
        coeff=coeff, 
        encryptedShareFile=sharefile)

    # Write the manifest file
    print(manifest)
    with open(f"{outdir}/{MANIFEST}", 'wt') as f:
      f.write(jsonEnc(manifest))

  def recover(self, bundle_dir):
    """
    Recover a secret from a bundle of encrypted shares.
    """
    # Load the manifest file.
    with open(f"{bundle_dir}/{MANIFEST}", 'rt') as f:
      manifest = jsonDec(f.read())

    # TODO: Verify the manifest contain the expected contents: k, n, etc
    k = manifest["K"]
    shares = {}
    for coeff, sharefile in identifyShares(manifest, k):
      ok, result = Crypto.decrypt(f"{bundle_dir}/{sharefile}")
      if not ok:
        print("ERROR: Decryption of {bundle_dir}/{sharefile} failed: {result}")
        exit(1)
      shares[coeff] = result

    # Recover the secret
    print(shares)
    print(b64enc(Crypto.recoverSecret(shares)))

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

  def recoverSecret(shares):
    """
    Receovers a secret from a dict {coeff: share}
    """
    return gfshare.combine(shares)

  def readPubkey():
    """
    Read the pubkey from an attached Yubikey
    """
    return run(
      ["pkcs15-tool", 
       "--read-public-key", Crypto.PKCS15_KEY_NUMBER])

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
      return se(result.stderr)

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
      cmdInput=plaintext)
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

  def fingerprintFile(filename):
    """
    Generates base64 encoded fingerprint using SHA256 over a file.
    Assumes small files.
    """
    blocksize = 65536
    with open(filename, 'rb') as f:
      return tb64enc(sha256(f.read()).digest())

  def fingerprint(datum):
    """
    Generates base64 encoded fingerprint using SHA256 over in-memory value.
    """
    return b64enc(sha256(toBytes(datum)).digest())

def identifyShares(manifest, k):
  """
  Prompts the user to insert a Yubikey, identify the device by it's pubkey 
  fingerprint and match that against a manifest entry. Continues until it
  recovers k shares.
  @yields: (coeff, sharefile)
  """
  for i in range(k):
    ok = False
    while not ok:
      input(f"Insert Yubikey and press <enter> [{i+1} of {k}]:")
      ok, pubkey = Crypto.readPubkey()

      if not ok:
        continue

      # TODO: Check pubkey against the manifest
      fp = Crypto.fingerprint(pubkey)
      # if not fp in manifest:
      #    print("Cannot find this pubkey in the manifest")
      #    continue
      # print(f"Located pubkey {fp} in manifest")

      # HACK: because we have only one yubikey for development
      coeff, sharefile = getShare(manifest)
      # coeff, sharefile = manifest[fp]
      print(f"{coeff}: {sharefile}")
      yield coeff, sharefile

# HACK: because we have only one yubikey for development
def getShare(manifest):
  for k,v in manifest.items():
    if k != "K" and k != "N":
      del manifest[k]
      return v

# Encode a bytes object in base64 and return a str object.
b64enc = lambda x: toStr(urlsafe_b64encode(x))

# Encode a bytes object in base64 and return a str object.
b64dec = lambda x: toBytes(urlsafe_b64decode(x))

def toStr(b):
  """
  Converts a utf-8 bytes object to a string.
  """
  if type(b) == str:
    return b
  else:
    return b.decode("utf-8")

def toBytes(b):
  """
  Converts a string to a bytes object by encoding it as utf-8.
  """
  if type(b) == str:
    return b.encode("utf-8")
  else:
    return b

def run(cmd):
  """
  Runs @cmd and captures stdout.
  """
  result = subprocess.run(cmd, stdout=PIPE)
  output =result.stdout
  return (result.returncode == 0, output)

def runWithStdin(cmd, cmdInput):
  """
  Runs @cmd, passes the string @cmdInput to the process, and 
  returns stdout or any errors.
  @returns (ok, output)
  """
  proc = subprocess.Popen(
    cmd, 
    stdin=PIPE,
    stdout=PIPE, 
    stderr=STDOUT)

  # Write the plaintext to STDIN
  proc.stdin.write(cmdInput)
  proc.stdin.close()

  # Wait for openssl to finish
  while proc.returncode is None:
    proc.poll()
    sleep(1)

  output = proc.stdout.read()
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

q recover BUNDLE_DIR [--out PATH] [--print]
Recover a secret from the encrypted bundle. Prompt for individual 
hardware devices to be inserted.

BUNDLE_DIR  The bundle of encrypted shares in a directory.
out         Write the output here; default is a temp file and path is printed
              to STDERR.
print       Print the recovered secret to STDOUT and don't write the output to
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
