"""
Q: a python library and command-line tool for managing a quorum of hardware 
devices (Yubikeys) required to unlock a secret.
"""
from subprocess import PIPE, STDOUT
from time import sleep
import subprocess
import fire

usage = \
"""
q COMMAND [OPTIONS]
Manage a quorum of hardware devices (Yubikeys) used to protect a secret.

COMMANDS

q newdevice
Print gpg instructions for initializing a new Yubikey with a public/private 
keypair.


q split K N [--keysize BITS] [--pubkeydir DIR] [--out PATH]
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

class Cli:
  def __init__(self):
    pass

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
  # -- not a requirement, just convention.
  # In the pkcs15-tool, this is designated key 3
  PRIVKEY_SLOT = "9c"
  KEY_NUMBER = "3"

  def __init__(self):
    pass

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
        "-a", "verify",
        "-s", Crypto.PRIVKEY_SLOT],
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
        "--key", Crypto.KEY_NUMBER]
      )
    # [file-encryption]: pkcs15-crypt --decipher -i test-file.enc t -o /dev/stdout --pkcs1 -p $PIN --key 3

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
  @returns (stdout, err)
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

  stdout = proc.stdout.read().decode('utf-8')
  proc.stdout.close()

  if proc.returncode == 0:
    return stdout, None
  else:
    return None, stdout

# Run!
if __name__ == '__main__':
  fire.Fire(Cli)
