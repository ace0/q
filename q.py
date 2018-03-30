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
SECRET_SHARE_MANIFEST = "shares-manifest.json"
DEVICE_MANIFEST = "device-manifest.json"

class Cli:
  """
  Command line interface to Q.
  """
  def __init__(self):
    pass

  def enroll(self, bundleDir="./bundle", adminPin=None, pin=None, 
    managementKey=None):
    """
    Enrolls a new Yubikey device for secrets management. 
    """
    # Converts numeric values to strings, but leaves None values the same.
    def strOrNone(x):
      if x is None:
        return None
      if type(x) == int:
        return str(x)
      else:
        return x

    adminPin = strOrNone(adminPin)
    pin = strOrNone(pin)
    managementKey = strOrNone(managementKey)

    # Prompt the operator to insert a device
    Crypto.promptDeviceInsertion()

    mgmKey = "010203040506070801020304050607080102030405060708"
    # TODO: Generate a random 24 byte management key and encode as hex
    # DEBUG: Disabled while we dev other things
    # print("Setting device management key")
    # ok, result = Crypto.setMgmKey(current=managementKey, new=mgmtKey)
    # if not ok:
    #   print(f"ERROR: Failed to set management key:\n{result}")
    # else:
    #   print("Established new management key")

    # TODO: Select random 8 digit pin
    # print("Setting administrative PIN")
    newAdminPin = "11002200"
    # DEBUG: Disabled during development
    # ok, _ = Crypto.setAdminPin(new=newAdminPin, current=adminPin)
    # if not ok:
    #   exit(1)
    # else:
    #   print("Established new admin pin")

    # TODO: Select random 6 digit pin
    newPin = "123456"
    # print("Setting operations PIN")
    # DEBUG: Disabled during development
    # ok, _ = Crypto.setPin(newPin, pin)
    # if not ok:
    #   exit(1)
    # else:
    # print("Established new user PIN")

    # TODO: On failure: we need to emit PIN, MGMTKEY, ADMIN PIN or device
    #       will be unusable

    # LEFT OFF: Need to generate pubkeyfile name to test this
    pubkeyfile = f"{bundleDir}/Test-device.pubkey"
    print("Generating new key pair on device")
    ok = Crypto.genPubkeyPair(pubkeyfile)
    if not ok:
      print("Failed to generate pubkey pair")
      exit(1)

    # TODO: Write particulars to a manifest file
    # Should we ditch the current fingerprint method and switch the 
    # fingerprint shown in yubic-piv-tool --action=status ?
    # Seems cleaner

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
    with open(f"{outdir}/{SECRET_SHARE_MANIFEST}", 'wt') as f:
      f.write(jsonEnc(manifest))

  def recover(self, bundle_dir):
    """
    Recover a secret from a bundle of encrypted shares.
    """
    # Load the manifest file.
    with open(f"{bundle_dir}/{SECRET_SHARE_MANIFEST}", 'rt') as f:
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

  # Default values for Yubikeys
  DEFAULT_PIN="123456"
  DEFAULT_ADMIN_PIN="12345678"
  DEFAULT_MGMT_KEY="010203040506070801020304050607080102030405060708"

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
    ok, result = run(
      ["yubico-piv-tool",
        "--action=generate",
        f"--slot={Crypto.YUBICO_PRIVKEY_SLOT}"])

    if not ok:
      return ok

    # Write the pubkey to a file
    with open(pubkeyfile, "wb") as out:
      out.write(result)

    return True

  def promptDeviceInsertion(msg="Insert Yubikey and press enter: "):
    """
    Prompts for the operator to insert a key and probes the device with 
    version command. Continues to prompt until a Yubikey is detected.
    """
    ok = False
    while not ok:
      input(msg)
      # The version command will fail if a Yubico device is not present.
      ok, _ = run(["yubico-piv-tool", "--action=version"], printErrorMsg=False)
      if not ok:
        print("Failed to detect device\n")

  def setAdminPin(new, current=None):
    """
    Sets a Yubikey administrative PIN (8 digits) used for unblocking the user 
    PIN after too many attempts). 
    If @current is not specified, uses the default admin PIN.
    """
    current = current or Crypto.DEFAULT_ADMIN_PIN
    def checkPin(p):
      if len(p) != 8:
        raise ValueError("Admin PIN (PUK) must be 8-digits")
    checkPin(new)
    checkPin(current)

    return run(
      ["yubico-piv-tool", 
       "--action=change-puk",
       f"--pin={current}",
       f"--new-pin={new}"])

  def setPin(new, current=None):
    """
    Sets the user PIN (6-digits)
    """
    current = current or Crypto.DEFAULT_PIN
    def checkPin(p):
      if len(p) != 6:
        raise ValueError("User PIN must be 6-digits")
    checkPin(new)
    checkPin(current)

    return run(
      ["yubico-piv-tool",
       "--action=change-pin",
       f"--pin={current}",
       f"--new-pin={new}"] )
    
  def setMgmKey(new, current=None):
    """
    Set the Yubikey management key (used to unblock and reconfigure the device)
    using the yubico-piv-tool (called via subprocess). If @current is not 
    specified, uses the default management key.
    """
    current = current or Crypto.DEFAULT_MGMT_KEY
    print(current)
    return run(
      ["yubico-piv-tool",
        f"--key={current}", 
        "--action=set-mgm-key",
        f"--new-key={new}"
        ])

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
      inputBytes=plaintext)
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

# Decode a base64 str and return a bytes object.
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

def run(cmd, echo=False, printErrorMsg=True):
  """
  Runs @cmd and captures stdout.
  """
  cmdString = " ".join(cmd)
  if echo:
    print(cmdString)
  result = subprocess.run(cmd, stdout=PIPE, stderr=PIPE)
  ok = (result.returncode == 0)

  # Handle any errors
  if ok:
    output = result.stdout
  else:
    output = toStr(result.stderr)

    if printErrorMsg:
      print(f"Error running command: {cmdString}\n{output}")

  return ok, output

def runWithStdin(cmd, inputString=None, inputBytes=None):
  """
  Runs @cmd, passes the string @inputString to the process (or the bytes
  object @inputBytes).
  @returns (ok, output)
  """
  # We must have exactly one of inputString, inputBytes set.
  if not (inputBytes or inputString):
    raise ValueError("inputString and inputBytes cannot both be None")

  if (inputString and inputBytes):
    raise ValueError("Only one of inputString and inputBytes can be set")

  # Convert our string to bytes if it was provided
  if inputString:
    inputBytes = toBytes(inputString)

  proc = subprocess.Popen(
    cmd, 
    stdin=PIPE,
    stdout=PIPE, 
    stderr=STDOUT)

  # Write the plaintext to STDIN
  proc.stdin.write(inputBytes)
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

q resplit BUNDLE_DIR K N [--pubkeydir DIR [--out PATH]
Recover and then re-split and re-encrypt a secret.
"""

# Run!
if __name__ == '__main__':
  fire.Fire(Cli)
