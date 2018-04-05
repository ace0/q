"""
Q: a python library and command-line tool for managing a quorum of hardware 
devices (Yubikeys) required to unlock a secret.
"""
from glob import glob
from hashlib import sha256
from secrets import token_bytes as randomBytes, token_hex as randomHex
import os, secrets, string
import gfshare, fire
from lib import *

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

    # Bail out on critical errors
    def exitOnFail(status, msg):
      if not status:
        print(msg)
        exit(1)

    # Prompt the operator to insert a device
    Crypto.promptDeviceInsertion()

    # Reset PINs and management keys
    ok, err, newPin, newAdminPin, newMgmKey = \
      Crypto.newAccessors(
        currentOpsPin=strOrNone(pin),
        currentAdminPin=strOrNone(adminPin),
        currentMgmKey=strOrNone(managementKey))
    exitOnFail(ok, err)

    # Generate new keys
    print("Generating new key pair on device")
    dm = DeviceManifest(bundleDir)
    devNumber, pubkeyfile = dm.newDevice()
    pubkeypath = f"{bundleDir}/{pubkeyfile}"

    ok = Crypto.genPubkeyPair(pubkeypath, managementKey=newMgmKey)
    exitOnFail(ok, "Failed to generate pubkey pair")

    ok, fp = Crypto.readPubkeyFingerprint()
    exitOnFail(ok, "Failed to read pubkey fingerprint from device")

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

  def split(self, k, n, length=128, bundleDir="./bundle"):
    """
    Generate a new secret, split it into shares, encrypt them, and write 
    them in a bundle to a file.
    """
    def fatal(msg):
      if msg:
        print(msg)
      exit(1)

    # Verify cmd line arguments
    k, n = int(k), int(n)

    if k > n:
      fatal(f"ERROR: K=({k}) cannot be larger than N(={n})")

    devices = DeviceManifest(bundleDir).devices()
    if n != len(devices):
      fatal(f"ERROR: The total number of shares, N, must match the number of "
        "public keys enrolled. Instead found N={n}, number of pubkeys="
        "{len(pubkeyfiles)}")

    shares = Crypto.splitSecret(bits=length, k=k, n=n)

    # Store information about each encrypted share
    shareManifest = ShareManifest.new(dir=bundleDir, k=k, n=n)

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
        pubkeyfile=f"{bundleDir}/{pubkeyFilename}", 
        ctxtfile=f"{bundleDir}/{sharefile}")
      if not ok:
        fatal()

      shareManifest.addShare(
        coeff=coeff,
        encryptedShareFile=sharefile,
        pubkeyFilename=device["pubkeyFilename"],
        pubkeyFingerprint=device["pubkeyFingerprint"])

    # Write the share manifest file
    shareManifest.write()

  def recover(self, bundle_dir):
    """
    Recover a secret from a bundle of encrypted shares.
    """
    # Load the manifest file.
    manifest = readManifest(f"{bundle_dir}/{SECRET_SHARE_MANIFEST}")

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

  def newAccessors(currentOpsPin=None, currentAdminPin=None, currentMgmKey=None):
    """
    Change the operations PIN, admin PIN, and management key on a Yubikey
    to secure, fresh, random values.
    @return (ok, errMsg, newOpsPin, newAdminPin, newMgmKey)
    """
    newOpsPin, newAdminPin, newMgmKey = (Crypto.randomPin(6), Crypto.randomPin(8), 
      randomHex(nbytes=24))

    # DEBUG: Here for development
    print(newOpsPin, newAdminPin, newMgmKey)

    establishedOpsPin = None
    establishedAdminPin = None
    establishedMgmKey = None

    # error = lambda msg: (False, msg, newOpsPin, newAdminPin, newMgmKey)

    try:
      ok, _ = Crypto.setMgmKey(current=currentMgmKey, new=newMgmKey)
      if not ok:
        raise ValueError("Failed to set management key", )
      establishedMgmKey = newMgmKey

      ok, _ = Crypto.setAdminPin(current=currentAdminPin, new=newAdminPin)
      if not ok:
        raise ValueError("Failed to set admin PIN")
      establishedAdminPin = newAdminPin

      ok, _ = Crypto.setPin(current=currentOpsPin, new=newOpsPin)
      if not ok:
        raise ValueError('Failed to set operations PIN (also called "user PIN")')
      establishedOpsPin = newOpsPin

    except Exception as e:
      print("An error occurred while attempting to change accessor codes on a Yubikey")

      # Print out any values that were set successfully, but haven't been recorded 
      # anywhere yet
      if establishedMgmKey or establishedAdminPin or establishedOpsPin:
        print("Established the following new values on the device:")
        if establishedOpsPin:
          print(f"Operations PIN (user PIN): {establishedOpsPin}")

        if establishedAdminPin:
          print(f"Admin PIN (PUK): {establishedAdminPin}")

        if establishedMgmKey:
          print(f"Management key: {establishedMgmKey}")

      return False, str(e), None, None, None


    return True, None, newOpsPin, newAdminPin, newMgmKey

  def randomPin(length):
    """
    Generates a (secure) random PIN of a given length.
    """
    return ''.join(secrets.choice(string.digits) for i in range(length))

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

  def readPubkeyFingerprint():
    """
    Reads the pubkey fingerprint from a fixed slot of a Yubikey device.
    """
    ok, result = run(
      ["yubico-piv-tool", 
       "--action=status"
      ])
    if not ok:
      return ok, result

    # Parse the status output and find the fingerprint for slot 9d
    slotFound = False    
    for line in result.decode().split("\n"):
      line = line.strip()
      if line.startswith(f"Slot {Crypto.YUBICO_PRIVKEY_SLOT}"):
        slotFound = True

      if slotFound and line.startswith("Fingerprint:"):
        fp = line.split(":")[1].strip()
        return True, fp

    # Output didn't match the expected output
    return False, None

  def genPubkeyPair(pubkeyfile, managementKey=None):
    """
    Generates a new pubkey pair on a Yubico device using the 
    yubico-piv-tool command (called via subprocess). Privkey is
    stored on the device and pubkey is written to pubkeyfile.
    """
    cmd = ["yubico-piv-tool",
        "--action=generate",
        f"--slot={Crypto.YUBICO_PRIVKEY_SLOT}"]
    if managementKey is not None:
      cmd.append(f"--key={managementKey}")

    ok, result = run(cmd)
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
    ok, _ = runWithStdin(
      cmd=["openssl", 
        "pkeyutl", "-encrypt",
        "-pubin",
        "-inkey", pubkeyfile,
        "-out", ctxtfile,
      ], 
      inputBytes=plaintext)
    return ok

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
      return b64enc(sha256(f.read()).digest())

  def fingerprint(datum):
    """
    Generates base64 encoded fingerprint using SHA256 over in-memory value.
    """
    return b64enc(sha256(toBytes(datum)).digest())

def purgeSharefiles(dir):
  """
  Remove any encrypted share files from a directory.
  """
  for file in glob(f"{dir}/share-*.ctxt"):
    os.remove(file)

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
