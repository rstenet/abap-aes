class ZCL_AES definition

* See https://github.com/rstenet/abap-aes

********************************************************************************
* The MIT License (MIT)
*
* Copyright (c) 2022 Robert Stefanov
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
********************************************************************************

  public
  final
  create private .

public section.

  class-methods DECRYPT_AES_GCM
    importing
      !CIPHER type XSTRING
      !KEY type XSTRING
      !IV type XSTRING
      !AAD type XSTRING optional
      !TAG type XSTRING
    exporting
      !PLAIN type XSTRING .
  class-methods ENCRYPT_AES_GCM
    importing
      !PLAIN type XSTRING
      !KEY type XSTRING
      !IV type XSTRING
      !AAD type XSTRING optional
    exporting
      !CIPHER type XSTRING
      !TAG type XSTRING .
  class-methods CRYPT_AES_CFB
    importing
      !INPUT type XSTRING
      !KEY type XSTRING
      !IV type XSTRING
      !ALGORITHM type STRING default CL_SEC_SXML_WRITER=>CO_AES256_ALGORITHM
      !DIR type C
    exporting
      !RESULT type XSTRING
    raising
      CX_SEC_SXML_ENCRYPT_ERROR
      CX_SY_DYN_CALL_ILLEGAL_METHOD .
protected section.
private section.

  class-methods GF_MULT
    importing
      !X type XSTRING
      !Y type XSTRING
    exporting
      !RESULT type XSTRING .
  class-methods GHASH
    importing
      !H type XSTRING
      !A type XSTRING optional
      !C type XSTRING
    exporting
      !GHASH type XSTRING .
  class-methods SHIFT_RIGHT
    importing
      !INPUT type X
    exporting
      !RESULT type XSTRING .
ENDCLASS.



CLASS ZCL_AES IMPLEMENTATION.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES=>CRYPT_AES_CFB
* +-------------------------------------------------------------------------------------------------+
* | [--->] INPUT                          TYPE        XSTRING
* | [--->] KEY                            TYPE        XSTRING
* | [--->] IV                             TYPE        XSTRING
* | [--->] ALGORITHM                      TYPE        STRING (default =CL_SEC_SXML_WRITER=>CO_AES256_ALGORITHM)
* | [--->] DIR                            TYPE        C
* | [<---] RESULT                         TYPE        XSTRING
* | [!CX!] CX_SEC_SXML_ENCRYPT_ERROR
* | [!CX!] CX_SY_DYN_CALL_ILLEGAL_METHOD
* +--------------------------------------------------------------------------------------</SIGNATURE>
  method CRYPT_AES_CFB.
    "ABAP implementation of AES cipher feedback mode
    DATA: blocksize  TYPE I value 16
        , keysize    TYPE I
        , cipher     TYPE XSTRING
        , block      TYPE XSTRING
        , rest       TYPE I
        , offset     TYPE I
        , l_iv       TYPE XSTRING
        , emptyiv    TYPE XSTRING value '00000000000000000000000000000000'
        , counter(4) TYPE X
        .

    CLEAR result.

    CASE ALGORITHM.
      WHEN cl_sec_sxml_writer=>CO_AES128_ALGORITHM_PEM OR
                  cl_sec_sxml_writer=>CO_AES128_ALGORITHM.
        keysize   = 16.
      WHEN cl_sec_sxml_writer=>CO_AES192_ALGORITHM_PEM OR
                  cl_sec_sxml_writer=>CO_AES192_ALGORITHM.
        keysize   = 24.
      WHEN cl_sec_sxml_writer=>CO_AES256_ALGORITHM_PEM OR
                  cl_sec_sxml_writer=>CO_AES256_ALGORITHM.
        keysize   = 32.
      WHEN OTHERS.
        RAISE EXCEPTION TYPE cx_sec_sxml_encrypt_error
          EXPORTING
            textid = cx_sec_sxml_encrypt_error=>invalid_algorithm.
    ENDCASE.

    IF xstrlen( iv ) NE blocksize OR xstrlen( key ) NE keysize.
      RAISE EXCEPTION TYPE cx_sec_sxml_encrypt_error
        EXPORTING
          textid = cx_sec_sxml_encrypt_error=>invalid_input
          msg    = 'CRYPT_AES_CFB'.
    ENDIF.

    rest = xstrlen( input ).

    IF rest < 1.
      RETURN. "nothing to encrypt
    ENDIF.

    l_iv = iv.

    DO.
      CALL METHOD cl_sec_sxml_writer=>encrypt_iv(
        EXPORTING
          plaintext  = l_iv
          key        = key
          iv         = emptyiv
          algorithm  = algorithm
        IMPORTING
          ciphertext = cipher ).

      IF xstrlen( cipher ) NE ( blocksize * 3 ). "iv + ciphertext + padding
        CLEAR result.
        RAISE EXCEPTION TYPE cx_sec_sxml_encrypt_error
          EXPORTING
            textid = cx_sec_sxml_encrypt_error=>crypt_error.
      ENDIF.

      IF rest > blocksize.
        block  = input+offset(blocksize).
        cipher = cipher+blocksize(blocksize).
      ELSE.
        block  = input+offset(rest).
        cipher = cipher+blocksize(rest).
      ENDIF.

      IF DIR = 'E'.     " Encrypt
        block = block BIT-XOR cipher.
        l_iv  = block.
      ELSEIF DIR = 'D'. " Decrypt
        l_iv  = block.
        block = block BIT-XOR cipher.
      ENDIF.

      CONCATENATE result block INTO result IN BYTE MODE.

      rest = rest - blocksize.
      offset = offset + blocksize.
      IF rest < 1.
        RETURN. "nothing more to encrypt
      ENDIF.

    ENDDO.
  endmethod.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES=>DECRYPT_AES_GCM
* +-------------------------------------------------------------------------------------------------+
* | [--->] CIPHER                         TYPE        XSTRING
* | [--->] KEY                            TYPE        XSTRING
* | [--->] IV                             TYPE        XSTRING
* | [--->] AAD                            TYPE        XSTRING(optional)
* | [--->] TAG                            TYPE        XSTRING
* | [<---] PLAIN                          TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  method DECRYPT_AES_GCM.
    "ABAP implementation of AES GCM mode
    DATA: algorithm  TYPE STRING
        , blocksize  TYPE I VALUE 16
        , keysize    TYPE I
        , block      TYPE XSTRING
        , rest       TYPE I
        , lenX(8)    TYPE x
        , pad        TYPE I
        , offset     TYPE I
        , l_iv       TYPE XSTRING
        , hash       TYPE XSTRING
        , y0         TYPE XSTRING
        , tmp        TYPE XSTRING
        , l_tag      TYPE XSTRING
        , emptyiv    TYPE XSTRING VALUE '00000000000000000000000000000000'
        , counter(4) TYPE X
        , ctroffset  TYPE I VALUE 12
        .

    CLEAR plain.

    keysize = xstrlen( key ).

    CASE keysize.
      WHEN 16.
        algorithm = cl_sec_sxml_writer=>CO_AES128_ALGORITHM.
      WHEN 24.
        algorithm =  cl_sec_sxml_writer=>CO_AES192_ALGORITHM.
      WHEN 32.algorithm = cl_sec_sxml_writer=>CO_AES256_ALGORITHM.
      WHEN OTHERS.
        RAISE EXCEPTION TYPE cx_sec_sxml_encrypt_error
          EXPORTING
            textid = cx_sec_sxml_encrypt_error=>invalid_algorithm.
    ENDCASE.

" In GCM initialization vector IV can have any number of bits
" between 1 and 2^64.
    IF xstrlen( iv ) LT 1 OR xstrlen( key ) NE keysize.
      RAISE EXCEPTION TYPE cx_sec_sxml_encrypt_error
        EXPORTING
          textid = cx_sec_sxml_encrypt_error=>invalid_input
          msg    = 'CRYPT_AES_GCM'.
    ENDIF.

    CALL METHOD cl_sec_sxml_writer=>crypt_aes_ctr(
      EXPORTING
        input     = emptyiv
        key       = key
        iv        = emptyiv
        algorithm = algorithm
      IMPORTING
        result    = hash ).

    IF xstrlen( iv ) = 12.
      counter = 1.
      l_iv = iv.
      CONCATENATE l_iv counter INTO l_iv IN BYTE MODE.
    ELSE.
      CALL METHOD ghash(
          EXPORTING
            H       = hash
            C       = iv
          IMPORTING
            GHASH   = l_iv ).
    ENDIF.

    CALL METHOD cl_sec_sxml_writer=>crypt_aes_ctr(
      EXPORTING
        input     = emptyiv
        key       = key
        iv        = l_iv
        algorithm = algorithm
      IMPORTING
        result    = y0 ).

    CALL METHOD ghash(
        EXPORTING
          H       = hash
          A       = aad
          C       = cipher
        IMPORTING
          GHASH   = tmp ).

    l_tag = y0 BIT-XOR tmp.

    " check tag
    IF tag NE l_tag.
      plain = '4641494C'.
      RETURN.
    ENDIF.


    "increment counter
    counter = l_iv+ctroffset.
    ADD 1 TO counter.
    CONCATENATE l_iv(ctroffset) counter INTO l_iv IN BYTE MODE.

    CALL METHOD cl_sec_sxml_writer=>crypt_aes_ctr(
      EXPORTING
        input     = cipher
        key       = key
        iv        = l_iv
        algorithm = algorithm
      IMPORTING
        result    = plain ).


  endmethod.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Public Method ZCL_AES=>ENCRYPT_AES_GCM
* +-------------------------------------------------------------------------------------------------+
* | [--->] PLAIN                          TYPE        XSTRING
* | [--->] KEY                            TYPE        XSTRING
* | [--->] IV                             TYPE        XSTRING
* | [--->] AAD                            TYPE        XSTRING(optional)
* | [<---] CIPHER                         TYPE        XSTRING
* | [<---] TAG                            TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  method ENCRYPT_AES_GCM.
    "ABAP implementation of AES GCM mode
    DATA: algorithm  TYPE STRING
        , blocksize  TYPE I VALUE 16
        , keysize    TYPE I
        , block      TYPE XSTRING
        , rest       TYPE I
        , lenX(8)    TYPE x
        , pad        TYPE I
        , offset     TYPE I
        , l_iv       TYPE XSTRING
        , hash       TYPE XSTRING
        , y0         TYPE XSTRING
        , tmp        TYPE XSTRING
        , emptyiv    TYPE XSTRING VALUE '00000000000000000000000000000000'
        , counter(4) TYPE X
        , ctroffset  TYPE I VALUE 12
        .

    CLEAR cipher.
    CLEAR tag.

    keysize = xstrlen( key ).

    CASE keysize.
      WHEN 16.
        algorithm = cl_sec_sxml_writer=>CO_AES128_ALGORITHM.
      WHEN 24.
        algorithm =  cl_sec_sxml_writer=>CO_AES192_ALGORITHM.
      WHEN 32.
        algorithm = cl_sec_sxml_writer=>CO_AES256_ALGORITHM.
      WHEN OTHERS.
        RAISE EXCEPTION TYPE cx_sec_sxml_encrypt_error
          EXPORTING
            textid = cx_sec_sxml_encrypt_error=>invalid_algorithm.
    ENDCASE.

" In GCM initialization vector IV , that can have any number of bits
" between 1 and 2^64.
    IF xstrlen( iv ) LT 1 OR xstrlen( key ) NE keysize.
      RAISE EXCEPTION TYPE cx_sec_sxml_encrypt_error
        EXPORTING
          textid = cx_sec_sxml_encrypt_error=>invalid_input
          msg    = 'CRYPT_AES_GCM'.
    ENDIF.

    CALL METHOD cl_sec_sxml_writer=>crypt_aes_ctr(
      EXPORTING
        input     = emptyiv
        key       = key
        iv        = emptyiv
        algorithm = algorithm
      IMPORTING
        result    = hash ).

    IF xstrlen( iv ) = 12.
      counter = 1.
      l_iv = iv.
      CONCATENATE l_iv counter INTO l_iv IN BYTE MODE.
    ELSE.
      CALL METHOD ghash(
          EXPORTING
            H       = hash
            C       = iv
          IMPORTING
            GHASH   = l_iv ).
    ENDIF.

    CALL METHOD cl_sec_sxml_writer=>crypt_aes_ctr(
      EXPORTING
        input     = emptyiv
        key       = key
        iv        = l_iv
        algorithm = algorithm
      IMPORTING
        result    = y0 ).

    "increment counter
    counter = l_iv+ctroffset.
    ADD 1 TO counter.
    CONCATENATE l_iv(ctroffset) counter INTO l_iv IN BYTE MODE.

    CALL METHOD cl_sec_sxml_writer=>crypt_aes_ctr(
      EXPORTING
        input     = plain
        key       = key
        iv        = l_iv
        algorithm = algorithm
      IMPORTING
        result    = cipher ).

    CALL METHOD ghash(
        EXPORTING
          H       = hash
          A       = aad
          C       = cipher
        IMPORTING
          GHASH   = tmp ).

    tag = y0 BIT-XOR tmp.

  endmethod.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Private Method ZCL_AES=>GF_MULT
* +-------------------------------------------------------------------------------------------------+
* | [--->] X                              TYPE        XSTRING
* | [--->] Y                              TYPE        XSTRING
* | [<---] RESULT                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  method GF_MULT.

    CLEAR RESULT.

    DATA: v(16)   TYPE x
        , e1(1)   TYPE x    VALUE 'E1'
        , last(1) TYPE x    VALUE '01'
        , i       TYPE int1 VALUE 0
        , j       TYPE int1 VALUE 0
        , bit(1)  TYPE x
        , tmp_x   TYPE xstring.

    v = y.

    DO 16 TIMES. " i
      DO 8 TIMES. " j
        bit = 2 ** ( 7 - j ).

        IF ( x+i(1) BIT-AND bit ) = bit.
          RESULT = RESULT BIT-XOR v.
        ENDIF.

        IF ( v+15(1) BIT-AND last ) = last.
          CALL METHOD shift_right
            EXPORTING
                INPUT  = v
            IMPORTING
                RESULT = tmp_x.
          v = tmp_x.
          v(1) = v(1) BIT-XOR e1.
        ELSE.
          CALL METHOD shift_right
            EXPORTING
                INPUT  = v
            IMPORTING
                RESULT = tmp_x.
          v = tmp_x.
        ENDIF.

        j = j + 1.
      ENDDO.
      j = 0.
      i = i + 1.
    ENDDO.

  endmethod.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Private Method ZCL_AES=>GHASH
* +-------------------------------------------------------------------------------------------------+
* | [--->] H                              TYPE        XSTRING
* | [--->] A                              TYPE        XSTRING(optional)
* | [--->] C                              TYPE        XSTRING
* | [<---] GHASH                          TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  method GHASH.

    DATA: len     TYPE I
        , pad     TYPE I
        , offset  TYPE I
        , l_c     TYPE XSTRING
        , len_ac  TYPE XSTRING
        , lenX(8) TYPE X
        , tmp     TYPE XSTRING VALUE '00000000000000000000000000000000'.
        .

    CLEAR ghash.

    len = xstrlen( c ).
    IF ( len mod 16 ) NE 0.
      pad = 16 - ( len mod 16 ).
    ENDIF.
    CONCATENATE c tmp(pad) INTO l_c IN BYTE MODE.
    lenX = ( len ) * 8.
    len_ac = lenX.

    IF a IS NOT INITIAL.
      pad = 0.
      len = XSTRLEN( a ).
      IF ( len mod 16 ) NE 0.
        pad = 16 - ( len mod 16 ).
      ENDIF.
      CONCATENATE a tmp(pad) l_c INTO l_c IN BYTE MODE.
      lenX = ( len )  * 8.
      CONCATENATE lenX len_ac INTO len_ac IN BYTE MODE.
    ELSE.
      lenX = 0.
      CONCATENATE lenX len_ac INTO len_ac IN BYTE MODE.
    ENDIF.

    len = xstrlen( l_c ).
    IF len < 1.
      RETURN. "nothing more to encrypt
    ENDIF.

    DO.
        IF len > 16.
          ghash  = l_c+offset(16).
        ELSE.
          ghash  = l_c+offset(len).
        ENDIF.

        ghash = ghash BIT-XOR tmp.

        CALL METHOD gf_mult
          EXPORTING
              x      = ghash
              y      = h
          IMPORTING
              RESULT = tmp.

        len = len - 16.
        offset = offset + 16.
        IF len < 1.
          EXIT. "nothing more to encrypt
        ENDIF.
    ENDDO.

    ghash = len_ac BIT-XOR tmp.

    CALL METHOD gf_mult
      EXPORTING
          x      = ghash
          y      = h
      IMPORTING
          RESULT = tmp.

    ghash = tmp.

  endmethod.


* <SIGNATURE>---------------------------------------------------------------------------------------+
* | Static Private Method ZCL_AES=>SHIFT_RIGHT
* +-------------------------------------------------------------------------------------------------+
* | [--->] INPUT                          TYPE        X
* | [<---] RESULT                         TYPE        XSTRING
* +--------------------------------------------------------------------------------------</SIGNATURE>
  method SHIFT_RIGHT.

  data: x(4)   TYPE x
      , first  TYPE x VALUE '80'
      , last   TYPE x VALUE '01'
      , i      TYPE INT8
      .

    CLEAR result.

    x = INPUT+12(4).  i = x.  x = i div 2.
    IF ( INPUT+11(1) BIT-AND last ) = last.
      x(1) = x(1) BIT-OR first.
    ENDIF.
    RESULT = x.

    x = INPUT+8(4).  i = x.  x = i div 2.
    IF ( INPUT+7(1) BIT-AND last ) = last.
      x(1) = x(1) BIT-OR first.
    ENDIF.
    CONCATENATE x RESULT INTO RESULT IN BYTE MODE.

    x = INPUT+4(4).  i = x.  x = i div 2.
    IF ( INPUT+3(1) BIT-AND last ) = last.
      x(1) = x(1) BIT-OR first.
    ENDIF.
    CONCATENATE x RESULT INTO RESULT IN BYTE MODE.

    x = INPUT(4).  i = x.  x = i div 2.
    CONCATENATE x RESULT INTO RESULT IN BYTE MODE.

  endmethod.
ENDCLASS.
