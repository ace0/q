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
    --new-pin=098765



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