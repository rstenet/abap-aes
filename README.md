# abap-aes

## ABAP implementation of additional (missing) AES modes of Operation.

The standard CL_SEC_SXML_WRITER=>{ENCRYPT/DECRYPT} are exposing AES only in Cipher Block Chaining (CBC) mode. 

There is also a method CRYPT_AES_CTR providing Counter Mode.
It is calling ENCRYPT_IV block by block, stripping 2/3 of the output each time, but you get Counter Mode.

So the missing modes are:
- Electronic Code Book (ECB)
- Cipher FeedBack mode (CFB)
- Output FeedBack mode (OFB)
- Galois/Counter Mode (GCM)

The aim of this ABAP class is to provide them unless SAP expose them to ABAP as the CommonCryptoLib used by the kernel calls is capable of doing all of them.
Currently only CFB and GCM are implemented. 
ECB and OFB are simple to do and will follow shortly.

GCM was more challenging as it requires other than encrypt/xor functions e.g. Multiplication in GF(2^128). 
