CLASS ltc_gcm_tests  DEFINITION FINAL FOR TESTING
                     DURATION SHORT
                     RISK LEVEL HARMLESS.

  PUBLIC SECTION.

  PRIVATE SECTION.

    METHODS:
      enc_dec_gcm FOR TESTING.

ENDCLASS.

CLASS ltc_gcm_tests IMPLEMENTATION.

  METHOD enc_dec_gcm.

      TYPES: BEGIN OF ty_gcm_test_cases,
             nr     TYPE I,
             key    TYPE xstring,
             iv     TYPE xstring,
             plain  TYPE xstring,
             aad    TYPE xstring,
             tag    TYPE xstring,
           END OF ty_gcm_test_cases.

      DATA: it_gcm_test_cases TYPE STANDARD TABLE OF ty_gcm_test_cases,
            wa_gcm_test_cases TYPE ty_gcm_test_cases,
            l_cipher TYPE xstring,
            l_plain  TYPE xstring,
            l_tag    TYPE xstring.

      " test case 1
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 1.
      wa_gcm_test_cases-key   = '00000000000000000000000000000000'.
      wa_gcm_test_cases-iv    = '000000000000000000000000'.
      wa_gcm_test_cases-tag   = '58E2FCCEFA7E3061367F1D57A4E7455A'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 2
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 3.
      wa_gcm_test_cases-key   = '00000000000000000000000000000000'.
      wa_gcm_test_cases-iv    = '000000000000000000000000'.
      wa_gcm_test_cases-plain = '00000000000000000000000000000000'.
      wa_gcm_test_cases-aad   = ''.
      wa_gcm_test_cases-tag   = 'AB6E47D42CEC13BDF53A67B21257BDDF'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 3
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 3.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBADDECAF888'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255'.
      wa_gcm_test_cases-tag   = '4D5C2AF327CD64A62CF35ABD2BA6FAB4'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 4
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 4.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBADDECAF888'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = '5BC94FBC3221A5DB94FAE95AE7121A47'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 5
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 5.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBAD'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = '3612D2E79E3B0785561BE14AACA2FCCB'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 6
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 6.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = '9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = '619CC5AEFFFE0BFA462AF43C1699D050'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 7
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 7.
      wa_gcm_test_cases-key   = '000000000000000000000000000000000000000000000000'.
      wa_gcm_test_cases-iv    = '000000000000000000000000'.
      wa_gcm_test_cases-tag   = 'CD33B28AC773F74BA00ED1F312572435'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 8
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 8.
      wa_gcm_test_cases-key   = '000000000000000000000000000000000000000000000000'.
      wa_gcm_test_cases-iv    = '000000000000000000000000'.
      wa_gcm_test_cases-plain = '00000000000000000000000000000000'.
      wa_gcm_test_cases-tag   = '2FF58D80033927AB8EF4D4587514F0FB'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 9
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 9.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBADDECAF888'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255'.
      wa_gcm_test_cases-tag   = '9924A7C8587336BFB118024DB8674A14'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 10
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 10.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBADDECAF888'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = '2519498E80F1478F37BA55BD6D27618C'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 11
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 11.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBAD'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = '65DCC57FCF623A24094FCCA40D3533F8'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 12
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 12.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_gcm_test_cases-iv    = '9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = 'DCF566FF291C25BBB8568FC3D376A6D9'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 13
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 13.
      wa_gcm_test_cases-key   = '0000000000000000000000000000000000000000000000000000000000000000'.
      wa_gcm_test_cases-iv    = '000000000000000000000000'.
      wa_gcm_test_cases-tag   = '530F8AFBC74536B9A963B4F1C4CB738B'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 14
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 14.
      wa_gcm_test_cases-key   = '0000000000000000000000000000000000000000000000000000000000000000'.
      wa_gcm_test_cases-iv    = '000000000000000000000000'.
      wa_gcm_test_cases-plain = '00000000000000000000000000000000'.
      wa_gcm_test_cases-tag   = 'D0D1C8A799996BF0265B98B5D48AB919'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 15
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 15.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBADDECAF888'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255'.
      wa_gcm_test_cases-tag   = 'B094DAC5D93471BDEC1A502270E3CC6C'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 16
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 16.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBADDECAF888'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = '76FC6ECE0F4E1768CDDF8853BB2D551B'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 17
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 17.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = 'CAFEBABEFACEDBAD'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = '3A337DBF46A792C45E454913FE2EA8F2'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 18
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 18.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = '9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = 'A44A8266EE1C8EB0C8B5D4CF5AE9F19A'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.

      " test case 19
      " it is like test 18 with last byte in TAG modified
      " so it shoult fail
      clear wa_gcm_test_cases.
      wa_gcm_test_cases-nr    = 19.
      wa_gcm_test_cases-key   = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_gcm_test_cases-iv    = '9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B'.
      wa_gcm_test_cases-plain = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_gcm_test_cases-aad   = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_gcm_test_cases-tag   = 'A44A8266EE1C8EB0C8B5D4CF5AE9F19B'.
      APPEND wa_gcm_test_cases TO it_gcm_test_cases.


      LOOP AT it_gcm_test_cases INTO wa_gcm_test_cases.

        zcl_aes=>encrypt_aes_gcm(
          EXPORTING
            plain      = wa_gcm_test_cases-plain
            key        = wa_gcm_test_cases-key
            iv         = wa_gcm_test_cases-iv
            aad        = wa_gcm_test_cases-aad
          IMPORTING
            cipher     = l_cipher
            tag        = l_tag
        ).

        zcl_aes=>decrypt_aes_gcm(
          EXPORTING
            cipher     = l_cipher
            key        = wa_gcm_test_cases-key
            iv         = wa_gcm_test_cases-iv
            aad        = wa_gcm_test_cases-aad
            tag        = l_tag
          IMPORTING
            plain      = l_plain
        ).

        cl_aunit_assert=>assert_equals(
          exp = wa_gcm_test_cases-tag
          act = l_tag
          msg = 'TAG - error in test case: ' && wa_gcm_test_cases-nr ).

      ENDLOOP.

  ENDMETHOD.

ENDCLASS.
