"""
Cryptographic and Yubikey operations.
"""
from secrets import token_bytes, token_hex as randomHex
from lib import *
import gfshare

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

  def splitSecret(bits=250, k=3, n=5):
    """
    Generate a new secret and split into shares
    """
    if k > n:
      raise ValueError(f"Quorum K cannot be larger than total number "
        "of shares N. Instead found K={k} and N={n}")

    secret = Crypto.randomBytes(bits=bits, noNullBytes=True)
    print("secret=", secret)
    print(len(secret))
    return gfshare.split(k, n, secret)

  def randomBytes(bits, noNullBytes):
    """
    Securely generates a fresh, random value. Ensures that value
    has no null bytes, if requested.
    """
    while True:
      value = token_bytes(nbytes=int(bits/8))
      if 0 not in value:
        return bytes(value)

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

  def readCertificate():
    """
    Read a certificate from an attached Yubikey.
    """
    return run(
      ["pkcs15-tool",
        "--read-certificate", Crypto.PKCS15_KEY_NUMBER])

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
    return (False, "yubico-piv-tool command output didn't match "
          "expected format")

  def genPubkeyPair(managementKey=None):
    """
    Generates a new pubkey pair on a Yubico device using the 
    yubico-piv-tool command (called via subprocess). Privkey is
    stored on the device and pubkey is written to pubkeyfile
    if a file path is specified.
    """
    cmd = ["yubico-piv-tool",
        "--action=generate",
        f"--slot={Crypto.YUBICO_PRIVKEY_SLOT}"]

    if managementKey is not None:
      cmd.append(f"--key={managementKey}")

    return run(cmd)

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

  def encrypt(plaintext, certfile, ctxtfile):
    """
    Encrypts (using OpenSSL called via subprocess) the plaintext 
    using a pubkey in certificate form read from a file. 
    The resulting ciphertext is written to ctxfile.
    """
    ok, _ = runWithStdin(
      cmd=["openssl", 
        "pkeyutl", "-encrypt",
        "-certin",
        "-inkey", certfile,
        "-out", ctxtfile,
      ], 
      inputString=plaintext)
    return ok

  def decrypt(ctxtfile, pin=None):
    """
    Decrypts a file (@ctxtfile) using a key stored on the Yubikey
    in our reserved slot. If (ops) PIN is not specified, the default
    value is used.
    """
    pin = pin or Crypto.DEFAULT_PIN
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
    with open(filename, 'rb') as f:
      return b64enc(sha256(f.read()).digest())

  def fingerprint(datum):
    """
    Generates base64 encoded fingerprint using SHA256 over in-memory value.
    """
    return b64enc(sha256(toBytes(datum)).digest())
