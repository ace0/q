"""
Common routines
"""
from base64 import urlsafe_b64encode, urlsafe_b64decode
from json import dumps as jsonEnc, loads as jsonDec
from time import sleep
from os.path import exists as pathExists
from subprocess import PIPE, STDOUT
import subprocess

##
# Manage manifest files

class JsonSerializable:
  """
  Classes that can be (de)serialized (from) to JSON.
  """
  def _getContents(self):
    """
    Subclasses implement this to retrieve a dictionary that will be serialized
    to JSON.
    """
    pass

  def write(self):
    """
    Writes a dictionary to a file in JSON format.
    """
    with open(self.path, 'wt') as f:
      f.write(jsonEnc(self._getContents(), sort_keys=True, indent=3))

  def _readJson(self):
    """
    Reads and decodes a JSON file.
    """
    with open(self.path, 'rt') as f:
      return jsonDec(f.read())

class ShareManifest(JsonSerializable):
  """
  Stores information about encrypted share files so that they can be
  reconstructed.
  """
  FILENAME = "shares-manifest.json"

  def __init__(self, directory):
    """
    Creates a new object. Callers should use .new() and .load() to
    create new manifests or read them from a file, respectively. 
    """
    self.path = f"{directory}/{ShareManifest.FILENAME}"

  def new(directory, n, k):
    """
    Creates a new secret share manifest that can be written 
    to the given directoryectory.
    """
    m = ShareManifest(directory)
    m.n = n
    m.k = k
    m.shares = {}
    return m

  def load(directory):
    """
    Reads an existing secret share manifest from the specified 
    directory.
    """
    m = ShareManifest(directory)
    m.path = f"{directory}/{ShareManifest.FILENAME}"

    # Read the manifest file and store entries as object attributes
    manifest = m._readJson()
    m.k = manifest["k"]
    m.n = manifest["n"]
    m.shares = manifest["shares"]
    return m

  def addShare(self, coeff, encryptedShareFile, 
    pubkeyFilename, pubkeyFingerprint):
    """
    Adds a new encrypted secret share entry to this manifest.
    """
    # TODO: Index shares by pubkey fingerprints
    #  But for development we want to re-use a single device
    self.shares[pubkeyFilename] = {
      "coeff": coeff, 
      "encryptedShareFile": encryptedShareFile,
      "pubkeyFilename": pubkeyFilename,
      "pubkeyFingerprint": pubkeyFingerprint
      }

  def _getContents(self):
    return {
      "k": self.k, 
      "n": self.n,
      "shares": self.shares
      }

class DeviceManifest(JsonSerializable):
  """
  Stores info about individual devices (Yubikeys) managed by Q.
  """
  FILENAME = "device-manifest.json"
  PUBKEY_BASENAME = "device-{number}.pubkey"

  def __init__(self, directory):
    self.path = f"{directory}/{self.FILENAME}"

    # Read the manifest if one exists
    if pathExists(self.path):
      self.deviceTable = self._readJson()
    else:
      self.deviceTable = {}

  def load(directory):
    """
    Load a device manifest file.
    """
    return DeviceManifest(directory)

  def findDevice(self, pubkeyFingerprint):
    """
    Finds the device entry that matches a pubkeyFingerprint.
    """
    for device in self.devices():
      if device["pubkeyFingerprint"] == pubkeyFingerprint:
        return device

  def devices(self):
    """
    Retrieves a list (of dictionaries) of all devices.
    """
    return list(self.deviceTable.values())

  def newDevice(self):
    """
    Generates a unique device number and pubkey filename for a new device.
    """
    dn = str(self._findUnusedDeviceNumber())
    pubkeyFilename = self.PUBKEY_BASENAME.format(number=dn)
    return dn, pubkeyFilename

  def addDevice(self, deviceNumber, pubkeyFilename, pubkeyFingerprint, 
    adminPin, operationsPin, managementKey):
    """
    Adds a new device to this manifest and re-writes the file.
    @returns pubkeyfilename
    """
    # TODO: Index these by device fingerprint to avoid duplicate devices
    #       and enable faster lookup
    #  But for debug we want to use the same yubikey mutiple times.
    self.deviceTable[deviceNumber] = {
        "number": deviceNumber,
        "pubkeyFilename": pubkeyFilename,
        "pubkeyFingerprint": pubkeyFingerprint,
        "operationsPin": operationsPin,
        "adminPin": adminPin,
        "managementKey": managementKey
      }

  def _getContents(self):
    return self.deviceTable

  def _findUnusedDeviceNumber(self):
    if len(self.deviceTable) == 0:
      return 1
    else:
      return max([int(d["number"]) for d in self.deviceTable.values()])+1

## 
# Utilities

def b64enc(x): 
  """
  Encode a bytes object in base64 and return a str object.
  """
  return toStr(urlsafe_b64encode(x))

def b64dec(x): 
  """
  Decode a base64 str and return a bytes object.
  """
  return toBytes(urlsafe_b64decode(x))

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

# TODO: Refactor into a single run()
#  with optional input and maybe even detect the type and apply
#  encoding automatically
# How to guess at the output?
# Maybe decodeStdout=True which reads stdout as text unless
#  otherwise specified.
# def run(cmd, echo, printErrorMsg, ...):
#  if echo: 
#    print()
#  if input:
#    _runWithStdin
#  else:
#    _run()
# 
#  if not ok and printErrorMSg()
#    if not echo:
#       echoNow()
#     print(error)
#  ...
def run(cmd, echo=True, printErrorMsg=True):
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

def runWithStdin(cmd, echo=True, inputString=None, inputBytes=None, printErrorMsg=True):
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

  if echo:
    print(" ".join(cmd))

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

  # Read and close stdout
  output = proc.stdout.read()
  proc.stdout.close()

  # Handle any errors
  ok = proc.returncode == 0
  if not ok and printErrorMsg:
    cmdString = " ".join(cmd)
    print(f"Error running command: {cmdString}\n{toStr(output)}")

  return ok, output

def exitOnFail(ok, msg=None):
  if not ok and msg:
    print(msg)
  if not ok:
    exit(1)

def strOrNone(x):
  """
  Converts numeric values to strings, but leaves None as None.
  """
  if x is None:
    return None
  if type(x) == int:
    return str(x)
  else:
    return x
