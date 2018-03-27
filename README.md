# Q
Use a quorum of hardware devices (Yubikeys) to protect and access a secret value. The seret value is split into a set of shares using Shamir's secret sharing. Shares are encrypted under public keys and the private (decryption) keys are stored on hardware devices (Yubikeys). A quorom of devices then are required to decrypt enough shares to reconstruct the protected secret.

### Prerequisites
- python 3
- libgfshare
- 

### Quickstart
MacOS:
```
brew install libgfshare
pip install gfshare
git clone https://github.com/ace0/q
```

