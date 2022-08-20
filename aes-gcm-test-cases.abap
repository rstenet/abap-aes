CLASS ltc_aes_tests  DEFINITION FINAL FOR TESTING
                     DURATION SHORT
                     RISK LEVEL HARMLESS.

  PUBLIC SECTION.

  PRIVATE SECTION.

    TYPES: BEGIN OF ty_tests
              , nr     TYPE I
              , key    TYPE xstring
              , iv     TYPE xstring
              , plain  TYPE xstring
              , aad    TYPE xstring
              , tag    TYPE xstring
              , cipher TYPE xstring
              , algo   TYPE string
              , END OF ty_tests.

    DATA: it_tests TYPE STANDARD TABLE OF ty_tests,
          wa_tests TYPE ty_tests,
          l_cipher          TYPE xstring,
          l_plain           TYPE xstring,
          l_tag             TYPE xstring.

    METHODS:
      enc_dec_gcm FOR TESTING,
      enc_dec_cfb FOR TESTING,
      enc_dec_ofb FOR TESTING,
      enc_dec_ecb FOR TESTING.

ENDCLASS.

CLASS ltc_aes_tests IMPLEMENTATION.

  METHOD enc_dec_gcm.

      clear it_tests.

      " test case 1
      clear wa_tests.
      wa_tests-nr     = 1.
      wa_tests-key    = '00000000000000000000000000000000'.
      wa_tests-iv     = '000000000000000000000000'.
      wa_tests-tag    = '58E2FCCEFA7E3061367F1D57A4E7455A'.
      APPEND wa_tests TO it_tests.

      " test case 2
      clear wa_tests.
      wa_tests-nr     = 2.
      wa_tests-key    = '00000000000000000000000000000000'.
      wa_tests-iv     = '000000000000000000000000'.
      wa_tests-plain  = '00000000000000000000000000000000'.
      wa_tests-cipher = '0388DACE60B6A392F328C2B971B2FE78'.
      wa_tests-tag    = 'AB6E47D42CEC13BDF53A67B21257BDDF'.
      APPEND wa_tests TO it_tests.

      " test case 3
      clear wa_tests.
      wa_tests-nr     = 3.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF888'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255'.
      wa_tests-cipher = '42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F5985'.
      wa_tests-tag    = '4D5C2AF327CD64A62CF35ABD2BA6FAB4'.
      APPEND wa_tests TO it_tests.

      " test case 4
      clear wa_tests.
      wa_tests-nr     = 4.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF888'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = '42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = '5BC94FBC3221A5DB94FAE95AE7121A47'.
      APPEND wa_tests TO it_tests.

      " test case 5
      clear wa_tests.
      wa_tests-nr     = 5.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBAD'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = '61353B4C2806934A777FF51FA22A4755699B2A714FCDC6F83766E5F97B6C742373806900E49F24B22B097544D4896B424989B5E1EBAC0F07C23F4598'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = '3612D2E79E3B0785561BE14AACA2FCCB'.
      APPEND wa_tests TO it_tests.

      " test case 6
      clear wa_tests.
      wa_tests-nr     = 6.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = '9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = '8CE24998625615B603A033ACA13FB894BE9112A5C3A211A8BA262A3CCA7E2CA701E4A9A4FBA43C90CCDCB281D48C7C6FD62875D2ACA417034C34AEE5'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = '619CC5AEFFFE0BFA462AF43C1699D050'.
      APPEND wa_tests TO it_tests.

      " test case 7
      clear wa_tests.
      wa_tests-nr     = 7.
      wa_tests-key    = '000000000000000000000000000000000000000000000000'.
      wa_tests-iv     = '000000000000000000000000'.
      wa_tests-tag    = 'CD33B28AC773F74BA00ED1F312572435'.
      APPEND wa_tests TO it_tests.

      " test case 8
      clear wa_tests.
      wa_tests-nr     = 8.
      wa_tests-key    = '000000000000000000000000000000000000000000000000'.
      wa_tests-iv     = '000000000000000000000000'.
      wa_tests-plain  = '00000000000000000000000000000000'.
      wa_tests-cipher = '98E7247C07F0FE411C267E4384B0F600'.
      wa_tests-tag    = '2FF58D80033927AB8EF4D4587514F0FB'.
      APPEND wa_tests TO it_tests.

      " test case 9
      clear wa_tests.
      wa_tests-nr     = 9.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF888'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255'.
      wa_tests-cipher = '3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710ACADE256'.
      wa_tests-tag    = '9924A7C8587336BFB118024DB8674A14'.
      APPEND wa_tests TO it_tests.

      " test case 10
      clear wa_tests.
      wa_tests-nr     = 10.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF888'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = '3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = '2519498E80F1478F37BA55BD6D27618C'.
      APPEND wa_tests TO it_tests.

      " test case 11
      clear wa_tests.
      wa_tests-nr     = 11.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_tests-iv     = 'CAFEBABEFACEDBAD'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = '0F10F599AE14A154ED24B36E25324DB8C566632EF2BBB34F8347280FC4507057FDDC29DF9A471F75C66541D4D4DAD1C9E93A19A58E8B473FA0F062F7'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = '65DCC57FCF623A24094FCCA40D3533F8'.
      APPEND wa_tests TO it_tests.

      " test case 12
      clear wa_tests.
      wa_tests-nr     = 12.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_tests-iv     = '9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = 'D27E88681CE3243C4830165A8FDCF9FF1DE9A1D8E6B447EF6EF7B79828666E4581E79012AF34DDD9E2F037589B292DB3E67C036745FA22E7E9B7373B'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = 'DCF566FF291C25BBB8568FC3D376A6D9'.
      APPEND wa_tests TO it_tests.

      " test case 13
      clear wa_tests.
      wa_tests-nr     = 13.
      wa_tests-key    = '0000000000000000000000000000000000000000000000000000000000000000'.
      wa_tests-iv     = '000000000000000000000000'.
      wa_tests-tag    = '530F8AFBC74536B9A963B4F1C4CB738B'.
      APPEND wa_tests TO it_tests.

      " test case 14
      clear wa_tests.
      wa_tests-nr     = 14.
      wa_tests-key    = '0000000000000000000000000000000000000000000000000000000000000000'.
      wa_tests-iv     = '000000000000000000000000'.
      wa_tests-plain  = '00000000000000000000000000000000'.
      wa_tests-cipher = 'CEA7403D4D606B6E074EC5D3BAF39D18'.
      wa_tests-tag    = 'D0D1C8A799996BF0265B98B5D48AB919'.
      APPEND wa_tests TO it_tests.

      " test case 15
      clear wa_tests.
      wa_tests-nr     = 15.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF888'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255'.
      wa_tests-cipher = '522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015AD'.
      wa_tests-tag    = 'B094DAC5D93471BDEC1A502270E3CC6C'.
      APPEND wa_tests TO it_tests.

      " test case 16
      clear wa_tests.
      wa_tests-nr     = 16.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF888'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = '522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = '76FC6ECE0F4E1768CDDF8853BB2D551B'.
      APPEND wa_tests TO it_tests.

      " test case 17
      clear wa_tests.
      wa_tests-nr     = 17.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBAD'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = 'C3762DF1CA787D32AE47C13BF19844CBAF1AE14D0B976AFAC52FF7D79BBA9DE0FEB582D33934A4F0954CC2363BC73F7862AC430E64ABE499F47C9B1F'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = '3A337DBF46A792C45E454913FE2EA8F2'.
      APPEND wa_tests TO it_tests.

      " test case 18
      clear wa_tests.
      wa_tests-nr     = 18.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = '9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B'.
      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
      wa_tests-cipher = '5A8DEF2F0C9E53F1F75D7853659E2A20EEB2B22AAFDE6419A058AB4F6F746BF40FC0C3B780F244452DA3EBF1C5D82CDEA2418997200EF82E44AE7E3F'.
      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
      wa_tests-tag    = 'A44A8266EE1C8EB0C8B5D4CF5AE9F19A'.
      APPEND wa_tests TO it_tests.

      " test case 19
      " it is like test 18 with last byte in TAG modified
      " so it shoult fail with TAG error
*      clear wa_tests.
*      wa_tests-nr     = 19.
*      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
*      wa_tests-iv     = '9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B'.
*      wa_tests-plain  = 'D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39'.
*      wa_tests-cipher = '5A8DEF2F0C9E53F1F75D7853659E2A20EEB2B22AAFDE6419A058AB4F6F746BF40FC0C3B780F244452DA3EBF1C5D82CDEA2418997200EF82E44AE7E3F'.
*      wa_tests-aad    = 'FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2'.
*      wa_tests-tag    = 'A44A8266EE1C8EB0C8B5D4CF5AE9F19B'.
*      APPEND wa_tests TO it_tests.


      LOOP AT it_tests INTO wa_tests.

        zcl_aes=>encrypt_aes_gcm(
          EXPORTING
            plain      = wa_tests-plain
            key        = wa_tests-key
            iv         = wa_tests-iv
            aad        = wa_tests-aad
          IMPORTING
            cipher     = l_cipher
            tag        = l_tag
        ).

        cl_aunit_assert=>assert_equals(
          exp = wa_tests-cipher
          act = l_cipher
          msg = 'Encryption error in test case: ' && wa_tests-nr ).

        zcl_aes=>decrypt_aes_gcm(
          EXPORTING
            cipher     = l_cipher
            key        = wa_tests-key
            iv         = wa_tests-iv
            aad        = wa_tests-aad
            tag        = l_tag
          IMPORTING
            plain      = l_plain
        ).

        cl_aunit_assert=>assert_equals(
          exp = l_plain
          act = wa_tests-plain
          msg = 'Enc - Dec error in test case: ' && wa_tests-nr ).

        cl_aunit_assert=>assert_equals(
          exp = wa_tests-tag
          act = l_tag
          msg = 'TAG - error in test case: ' && wa_tests-nr ).

      ENDLOOP.

  ENDMETHOD.

  METHOD enc_dec_cfb.

      clear it_tests.

      " aes 128 cfb
      clear wa_tests.
      wa_tests-nr     = 21.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF88800000000'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = '562C695C556D4B6FD4D342FB64ACE261D7026008B150328D27EEBDD105879F29DAC70366A6DA79B19A792A627C0F816B'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes128_algorithm.
      APPEND wa_tests TO it_tests.

      " aes 192 cfb
      clear wa_tests.
      wa_tests-nr     = 22.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF88800000000'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = '290E2260E8CBFEBF7094FBFC1C0B7914AB15A8C23C738926FE36456D70247BA5C4E8271B254355EC596E204EAA4AA3D3'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes192_algorithm.
      APPEND wa_tests TO it_tests.

      " aes 256 cfb
      clear wa_tests.
      wa_tests-nr     = 23.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF88800000000'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = '25412DE8F6F4AD985BD16F146C3993F9DA3EC326137EA199687696E7275155A1BB5B6CE50F78A16249E89388E2CC1433'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes256_algorithm.
      APPEND wa_tests TO it_tests.

      LOOP AT it_tests INTO wa_tests.

        zcl_aes=>encrypt_aes_cfb(
          EXPORTING
            plain      = wa_tests-plain
            key        = wa_tests-key
            iv         = wa_tests-iv
            algorithm  = wa_tests-algo
          IMPORTING
            cipher     = l_cipher
        ).

        cl_aunit_assert=>assert_equals(
          exp = wa_tests-cipher
          act = l_cipher
          msg = 'Encryption error in test case: ' && wa_tests-nr ).

        zcl_aes=>decrypt_aes_cfb(
          EXPORTING
            cipher     = l_cipher
            key        = wa_tests-key
            iv         = wa_tests-iv
            algorithm  = wa_tests-algo
          IMPORTING
            plain      = l_plain
        ).

        cl_aunit_assert=>assert_equals(
          exp = l_plain
          act = wa_tests-plain
          msg = 'Enc - Dec error in test case: ' && wa_tests-nr ).

      ENDLOOP.

  ENDMETHOD.

  METHOD enc_dec_ofb.

      clear it_tests.

      " aes 128 ofb
      clear wa_tests.
      wa_tests-nr     = 41.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF88800000000'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = '562C695C556D4B6FD4D342FB64ACE2619097A49BD48BA27AC9AC8F9201C81F3F7620153005A4F69B58B08983DD7C43C1'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes128_algorithm.
      APPEND wa_tests TO it_tests.

      " aes 192 ofb
      clear wa_tests.
      wa_tests-nr     = 42.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF88800000000'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = '290E2260E8CBFEBF7094FBFC1C0B7914F0CDB508583678BE58A6AA9A25568FD2033B7B9D97BE1C5FFA3EC77BDC8D447D'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes192_algorithm.
      APPEND wa_tests TO it_tests.

      " aes 256 ofb
      clear wa_tests.
      wa_tests-nr     = 43.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-iv     = 'CAFEBABEFACEDBADDECAF88800000000'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = '25412DE8F6F4AD985BD16F146C3993F9E1A7008AC9AC55802AA0040805582E8788A78E533CB02955323E615938B0F30B'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes256_algorithm.
      APPEND wa_tests TO it_tests.

      LOOP AT it_tests INTO wa_tests.

        zcl_aes=>crypt_aes_ofb(
          EXPORTING
            input      = wa_tests-plain
            key        = wa_tests-key
            iv         = wa_tests-iv
            algorithm  = wa_tests-algo
          IMPORTING
            result     = l_cipher
        ).

        cl_aunit_assert=>assert_equals(
          exp = wa_tests-cipher
          act = l_cipher
          msg = 'Encryption error in test case: ' && wa_tests-nr ).


        zcl_aes=>crypt_aes_ofb(
          EXPORTING
            input      = l_cipher
            key        = wa_tests-key
            iv         = wa_tests-iv
            algorithm  = wa_tests-algo
          IMPORTING
            result     = l_plain
        ).

        cl_aunit_assert=>assert_equals(
          exp = l_plain
          act = wa_tests-plain
          msg = 'Enc - Dec error in test case: ' && wa_tests-nr ).

      ENDLOOP.


  ENDMETHOD.

  METHOD enc_dec_ecb.

      clear it_tests.

      " aes 128 ecb
      clear wa_tests.
      wa_tests-nr     = 31.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = 'E8E03A60FC7F0D9E36E472842CC09C4C90CE8643E2EB097E1342296647EF20088909415A80D72B88941BAFFD1565609E'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes128_algorithm.
      APPEND wa_tests TO it_tests.

      " aes 192 ecb
      clear wa_tests.
      wa_tests-nr     = 32.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = 'B1217F6EEA8A345ADAD0EF837FCA0DF7A939C1326A640C8F688DCECF8F4DBD732C6669D832DBBA44C4CCAD0C7325E36C'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes192_algorithm.
      APPEND wa_tests TO it_tests.

      " aes 256 ecb
      clear wa_tests.
      wa_tests-nr     = 33.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = '2C8A388D0C767BC058251FE4C9CC45C48BFB3260B6369E49C77C69C783E17802928358E1A50C28A1647B87F5C9A97CEF'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes256_algorithm.
      APPEND wa_tests TO it_tests.

      " aes 128 ecb
      clear wa_tests.
      wa_tests-nr     = 34.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = 'E8E03A60FC7F0D9E36E472842CC09C4C90CE8643E2EB097E1342296647EF20088909415A80D72B88941BAFFD1565609E'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes128_algorithm_pem.
      APPEND wa_tests TO it_tests.

      " aes 192 ecb
      clear wa_tests.
      wa_tests-nr     = 35.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = 'B1217F6EEA8A345ADAD0EF837FCA0DF7A939C1326A640C8F688DCECF8F4DBD732C6669D832DBBA44C4CCAD0C7325E36C'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes192_algorithm_pem.
      APPEND wa_tests TO it_tests.

      " aes 256 ecb
      clear wa_tests.
      wa_tests-nr     = 36.
      wa_tests-key    = 'FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308'.
      wa_tests-plain  = '496E20612064697374616E7420616E64207365636F6E642D68616E6420736574206F662064696D656E73696F6E730102'.
      wa_tests-cipher = '2C8A388D0C767BC058251FE4C9CC45C48BFB3260B6369E49C77C69C783E17802928358E1A50C28A1647B87F5C9A97CEF'.
      wa_tests-algo   = cl_sec_sxml_writer=>co_aes256_algorithm_pem.
      APPEND wa_tests TO it_tests.


      LOOP AT it_tests INTO wa_tests.

        zcl_aes=>encrypt_aes_ecb(
          EXPORTING
            plain      = wa_tests-plain
            key        = wa_tests-key
            algorithm  = wa_tests-algo
          IMPORTING
            cipher     = l_cipher
        ).

        cl_aunit_assert=>assert_equals(
          exp = wa_tests-cipher
          act = l_cipher
          msg = 'Encryption error in test case: ' && wa_tests-nr ).

        zcl_aes=>decrypt_aes_ecb(
          EXPORTING
            cipher     = l_cipher
            key        = wa_tests-key
            algorithm  = wa_tests-algo
          IMPORTING
            plain      = l_plain
        ).

        cl_aunit_assert=>assert_equals(
          exp = l_plain
          act = wa_tests-plain
          msg = 'Enc - Dec error in test case: ' && wa_tests-nr ).

      ENDLOOP.

  ENDMETHOD.


ENDCLASS.
