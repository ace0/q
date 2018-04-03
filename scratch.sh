yubico-piv-tool \
    --key="050105010501050105010501050105010501050105010501" \
    --action=set-mgm-key \
    --new-key="010203040506070801020304050607080102030405060708"


    --key="010203040506070801020304050607080102030405060708" \

yubico-piv-tool \
    --action=change-puk \
    --pin=12345678 \
    --new-pin=11223344

yubico-piv-tool \
    --action=change-pin \
    --pin=123456 \
    --new-pin=204060

 -a, --action=ENUM        Action to take  (possible values="version",
                             "generate", "set-mgm-key", "reset",
                             "pin-retries", "import-key",
                             "import-certificate", "set-chuid",
                             "request-certificate", "verify-pin",
                             "change-pin", "change-puk", "unblock-pin",
                             "selfsign-certificate", "delete-certificate",
                             "read-certificate", "status",
                             "test-signature", "test-decipher",
                             "list-readers", "set-ccc", "write-object",
                             "read-object", "attest")

       Multiple actions may be given at once and will be executed in order
       for example --action=verify-pin --action=request-certificate

--pin=STRING         Pin/puk code for verification, if omitted pin/puk
                             will be asked for
  -N, --new-pin=STRING     New pin/puk code for changing, if omitted pin/puk
                             will be asked for


# Current Accessor codes
adminPin=12345678
pin=123456

# I think this one:
managementKey=e5569eadbf27e1b41e42ef5e92bcaf34ff04873212bbbb7448e96140c58ea0e1

# Doesn't work
# 8a8624b751df18da63a6320a388744aac69a3b4c4cfe3f4f
# a1840153342a5bb99e1c2a4a88329b89623399f4b6d0389c
# bc65ea914d845246f2b98fd3d29125fb8bc006b89b728813
# 14e8235cdc4f1190d378dc58477c513bd0cb6a3f899b7929

export  MGM=4ad18ef0098cb6f6deaff5e5f33dad9bb596614f73f116c9
DEFAULT_KEY=010203040506070801020304050607080102030405060708
yubico-piv-tool --key=$MGM --action=set-mgm-key --new-key=$DEFAULT_KEY

