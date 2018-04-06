"""
Q: a python library and command-line tool for managing a quorum of hardware 
devices (Yubikeys) required to unlock a secret.
"""
from glob import glob
from hashlib import sha256
import os, secrets, string
from lib import *
from crypto import Crypto

import fire

# Constants
DEFAULT_BUNDLE_DIR = "./bundle"

# LEFT OFF: 
# 
# openssl ... -certin ...
# and pkcs15-crypt ... --pkcs1 ...
#  works
# So:
# - Test that it works with bytes() values through a test line
# - Change device enrollment to output certs
# - Fix split
# - Fix recover

class Cli:
  """
  Command line interface to Q.
  """
  def enroll(self, bundleDir=DEFAULT_BUNDLE_DIR, adminPin=None, 
    pin=None, managementKey=None, changeAccessors=True):
    """
    Enrolls a new Yubikey device for secrets management. 
    """
    # Prompt the operator to insert a device
    Crypto.promptDeviceInsertion()

    # Reset PINs and management keys
    if changeAccessors:
      ok, err, newPin, newAdminPin, newMgmKey = \
        Crypto.newAccessors(
          currentOpsPin=strOrNone(pin),
          currentAdminPin=strOrNone(adminPin),
          currentMgmKey=strOrNone(managementKey))
      exitOnFail(ok, err)
    else:
      newPin = strOrNone(pin)
      newAdminPin = strOrNone(adminPin)
      newMgmKey = strOrNone(managementKey)

    # Generate new keys
    print("Generating new key pair on device")
    dm = DeviceManifest(bundleDir)
    devNumber, pubkeyfile = dm.newDevice()
    pubkeypath = f"{bundleDir}/{pubkeyfile}"

    ok, _ = Crypto.genPubkeyPair(managementKey=newMgmKey)
    exitOnFail(ok, "Failed to generate pubkey pair")

    ok, fp = Crypto.readPubkeyFingerprint()
    exitOnFail(ok, "Failed to read pubkey fingerprint from device")

    # Write the device certificate to a file.
    # NOTE: We've tried encrypt(openssl)/decrypt(pkcs15-crypt) 
    # using pubkeys not certs. We were never able to get padding to
    # work correctly. Instead we encrypt with cert and decrypt on
    # Yubikey.
    ok, cert = Crypto.readCertificate()
    exitOnFail(ok)
    with open(pubkeypath, 'wb') as f:
      f.write(cert)

    # Update the device manifest 
    dm.addDevice(
      deviceNumber=devNumber, 
      pubkeyFilename=pubkeyfile, 
      pubkeyFingerprint=fp, 
      adminPin=newAdminPin, 
      operationsPin=newPin, 
      managementKey=newMgmKey)
    dm.write()
    print("Manifest updated. Device enrolled.")

  def split(self, k, n, length=128, bundleDir=DEFAULT_BUNDLE_DIR):
    """
    Generate a new secret, split it into shares, encrypt them, and write 
    them in a bundle to a file.
    """
    # Verify cmd line arguments
    k, n = int(k), int(n)
    exitOnFail(k <= n, f"ERROR: K=({k}) cannot be larger than N(={n})")

    devices = DeviceManifest(bundleDir).devices()
    exitOnFail(n == len(devices), 
      f"ERROR: The total number of shares, N, must match the number of "
      "public keys enrolled. Instead found N={n}, number of pubkeys="
      "{len(pubkeyfiles)}")

    shares = Crypto.splitSecret(bits=length, k=k, n=n)

    # Store information about each encrypted share
    shareManifest = ShareManifest.new(directory=bundleDir, k=k, n=n)

    # Remove any existing sharefiles in the directory
    purgeSharefiles(bundleDir)

    # Encrypt each share under a distinct pubkey
    for (device, (coeff, share)) in zip(devices, shares.items()):
      # Grab the pubkey filename independent of the directory
      pubkeyFilename = device["pubkeyFilename"]

      # Encrypt the share and write it to a file
      sharefile = f"share-{coeff}.ctxt"
      ok = Crypto.encrypt(
        plaintext=share,
        certfile=f"{bundleDir}/{pubkeyFilename}", 
        ctxtfile=f"{bundleDir}/{sharefile}")
      exitOnFail(ok)

      shareManifest.addShare(
        coeff=coeff,
        encryptedShareFile=sharefile,
        pubkeyFilename=device["pubkeyFilename"],
        pubkeyFingerprint=device["pubkeyFingerprint"])

    # Write the share manifest file
    shareManifest.write()

  def recover(self, bundleDir=DEFAULT_BUNDLE_DIR):
    """
    Recover a secret from a bundle of encrypted shares.
    """
    # Load the manifest files.
    shareManifest = ShareManifest.load(bundleDir)
    deviceManifest = DeviceManifest.load(bundleDir)

    # TODO: Verify the shareManifest contain the expected contents: k, n, etc
    shares = {}
    shareMatcher = identifyShares(
      sharesTable=shareManifest.shares, 
      k=shareManifest.k)

    # Process k Yubikeys that match share files
    for coeff, sharefile, pkfp in shareMatcher:
      # Find the device so we can get it's PIN for decryption
      device = deviceManifest.findDevice(pubkeyFingerprint=pkfp)
      exitOnFail(device is not None, 
        msg=f"Failed to find device in manifest file with "
          "pubkeyFingerprint={pkfp}")

      # Decrypt the sharenand store the result
      ok, result = Crypto.decrypt(
        ctxtfile=f"{bundleDir}/{sharefile}",
        pin=device["operationsPin"])
      exitOnFail(ok)

      shares[coeff] = result

    # Recover the secret
    print(Crypto.recoverSecret(shares))

  def encrypt(self, pubkeyfile, ctxtfile):
    ok = Crypto.encrypt(
      plaintext="hello, world",
      pubkeyfile=pubkeyfile,
      ctxtfile=ctxtfile)
    if not ok:
      print(f"ERROR: during encryption")

  def decrypt(self, ctxtfile):
    ok, result = Crypto.decrypt(ctxtfile, pin="685828")
    if ok:
      print(f"Recovered: '{result}'")
    else:
      print(f"ERROR: {result}")

  def test(self):
    # Encrypt/decrypt round trip does not give expected results
    # Probably need unit test 

    pkfile = "bundle/device-1.pubkey"
    ctxfile = "test.ctxt"
    self.encrypt(pkfile, ctxfile)
    self.decrypt(ctxfile)

def purgeSharefiles(dir):
  """
  Remove any encrypted share files from a directory.
  """
  for file in glob(f"{dir}/share-*.ctxt"):
    os.remove(file)

def identifyShares(sharesTable, k):
  """
  Prompts the user to insert a Yubikey, identify the device by it's pubkey 
  fingerprint and match that against a shareManifest entry. Continues until it
  recovers k shares.
  @yields: (coeff, sharefile, pubkeyFingerprint)
  """
  for i in range(k):
    # HACK: Instead of using yielding this value, we're using
    # this call to ensure that a yubikey with some known
    # fingerprint is inserted
    # Then we return shares in order because we're using a
    # single yubikey for development

    # yield matchYubikey(
    matchYubikey(
      sharesTable=sharesTable,
      prompt=f"Insert Yubikey and press enter [{i+1}/{k}]: ")

    entry = list(sharesTable.values())[i]
    yield (entry["coeff"], entry["encryptedShareFile"], 
          entry["pubkeyFingerprint"])

def matchYubikey(sharesTable, prompt):
  """
  Prompts for a device to be inserted and ensures that device matches
  some device associated with an encrypted sharefile by matching against
  the pubkeyfingerprint. 
  Continues prompting until a yubikey is inserted that matches some entry
  in the shares manifest
  """
  while True:
    # Read the pubkey fingerprint for the inserted device
    Crypto.promptDeviceInsertion(msg=prompt)
    ok, pkfp = Crypto.readPubkeyFingerprint()

    if not ok:
      raise RuntimeError("Failed to read pubkey fingerprint")

    # Find the right sharefile for this key

    # TODO: When we index shares by pubkey fingerprint this is 
    #       much simpler
    # if pkfp not in shareManifest["shares"]:
    for key, entry in sharesTable.items():
      if entry["pubkeyFingerprint"] == pkfp:
        return entry["coeff"], entry["encryptedShareFile"]

    print("This device doesn't match any shares")

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
length     The size of the new secret in bits; default=128.
bundleDir  Directory that stores device and pubkey information; output written
           here as well; default=./bundle

q recover [--bundleDir DIR] [--out PATH] [--print]
Recover a secret from the encrypted bundle. Prompt for individual 
hardware devices to be inserted.

bundleDir   Directory containing encrypted shares and device information.
out         Write the recovered secret here; default is a temp file and path is printed
              to STDOUT.
print       Print the recovered secret to STDOUT and don't write the output to
              a file.

q resplit K N [--pubkeydir DIR [--out PATH] [--bundleDir DIR]
Recover and then re-split and re-encrypt a secret.
"""

# Run!
if __name__ == '__main__':
  fire.Fire(Cli)
