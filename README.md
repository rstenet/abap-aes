# abap-aes

## ABAP implementation of additional AES modes of Operation.

The standard CL_SEC_SXML_WRITER=>{ENCRYPT/DECRYPT} are exposing AES only in Cipher Block Chaining (CBC) mode. 

There is also a method CL_SEC_SXML_WRITER=>CRYPT_AES_CTR providing Counter Mode.
It is calling ENCRYPT_IV block by block, stripping 2/3 of the output each cycle.

This class implements the following modes:
- (ECB) Electronic Code Book
- (CFB) Cipher FeedBack
- (OFB) Output FeedBack
- (GCM) Galois/Counter

For GCM only 128 bit TAG length is implemented. 
