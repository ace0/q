"""
Common routines
"""
# from base64 import urlsafe_b64encode, urlsafe_b64decode
# from collections import namedtuple
# from glob import glob
# from hashlib import sha256
from json import dumps as jsonEnc, loads as jsonDec
# from subprocess import PIPE, STDOUT
# from secrets import token_bytes as randomBytes, token_hex as randomHex
# from time import sleep

from os.path import exists as pathExists

# import secrets, subprocess, string


##
# Manifest files
class ManifestBase:
  """
  Common routines for managing manifest files
  """
  def write(self):
    """
    Writes a dictionary to a file in JSON format.
    """
    with open(self.path, 'wt') as f:
      f.write(jsonEnc(self.manifest))

  def _readManifest(self, path):
    """
    Reads and decodes a JSON manifest file.
    """
    with open(path, 'rt') as f:
      return jsonDec(f.read())

class ShareManifest(ManifestBase):
  """
  Stores information about encrypted share files so that they can be
  reconstructed.
  """
  MANIFEST_FILENAME = "shares-manifest.json"

  def new(dir, n, k):
    """
    Creates a new secret share manifest that can be written 
    to the given directory.
    """
    m = ShareManifest()
    m.path = f"{dir}/{ShareManifest.MANIFEST_FILENAME}"
    m.manifest = {"K": k, "N":n, "shares": {}}
    return m

  def load(dir):
    """
    Reads an existing secret share manifest from the specified 
    directory.
    """
    m = ShareManifest()
    m.path = f"{dir}/{self.MANIFEST_FILENAME}"
    m._readManifest(m.path)
    return m

  def addShare(self, coeff, encryptedShareFile, 
    pubkeyFilename, pubkeyFingerprint):
    """
    Adds a new encrypted secret share entry to this manifest.
    """
    # TODO: Index shares by pubkey fingerprints
    #  But for development we want to re-use a single device
    self.manifest["shares"][pubkeyFilename] = {
      "coeff": coeff, 
      "encryptedShareFile": encryptedShareFile,
      "pubkeyFilename": pubkeyFilename,
      "pubkeyFingerprint": pubkeyFingerprint
      }

class DeviceManifest(ManifestBase):
  """
  Stores info about individual devices (Yubikeys) managed by Q.
  """
  MANIFEST_FILENAME = "device-manifest.json"
  PUBKEY_BASENAME = "device-{number}.pubkey"

  def __init__(self, dir):
    self.path = f"{dir}/{self.MANIFEST_FILENAME}"

    # Read the manifest if there is one
    if pathExists(self.path):
      self.manifest = self._readManifest(self.path)
    else:
      self.manifest = {}

  def devices(self):
    """
    Retrieves a list (of dictionaries) of all devices.
    """
    return list(self.manifest.values())

  def newDevice(self):
    """
    Generates a unique device number and pubkey filename for a new device.
    """
    dn = self._findUnusedDeviceNumber()
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
    self.manifest[deviceNumber] = {
        "number": deviceNumber,
        "pubkeyFilename": pubkeyFilename,
        "pubkeyFingerprint": pubkeyFingerprint,
        "operationsPin": operationsPin,
        "adminPin": adminPin,
        "managementKey": managementKey
      }

  def _findUnusedDeviceNumber(self):
    if len(self.manifest) == 0:
      return 1
    else:
      return max([int(d["number"]) for d in self.manifest.values()])+1