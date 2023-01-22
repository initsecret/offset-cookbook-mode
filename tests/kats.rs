use aead::{AeadInPlace, KeyInit};
use aes::Block;
use hex_literal::hex;
use offset_cookbook_mode::ocb3::{Aes128Ocb3, Key};

/// Test vectors from https://www.rfc-editor.org/rfc/rfc7253.html#appendix-A
#[test]
fn rfc7253_sample_results() {
    let key = Key::from(hex!("000102030405060708090A0B0C0D0E0F"));
    struct Kat {
        nonce: Vec<u8>,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>,
    }
    let kats = [
            Kat {
                nonce: hex!("BBAA99887766554433221100").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("785407BFFFC8AD9EDCC5520AC9111EE6").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221101").to_vec(),
                associated_data: hex!("0001020304050607").to_vec(),
                plaintext: hex!("0001020304050607").to_vec(),
                ciphertext: hex!("6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221102").to_vec(),
                associated_data: hex!("0001020304050607").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("81017F8203F081277152FADE694A0A00").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221103").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("0001020304050607").to_vec(),
                ciphertext: hex!("45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221104").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F").to_vec(),
                ciphertext: hex!(
                    "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358"
                )
                .to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221105").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("8CF761B6902EF764462AD86498CA6B97").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221106").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F").to_vec(),
                ciphertext: hex!(
                    "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D"
                )
                .to_vec(),
            },
            Kat {
                 nonce: hex!("BBAA99887766554433221107").to_vec(),
                 associated_data: hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec(),
                 plaintext: hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec(),
                 ciphertext: hex!("1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221108").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("6DC225A071FC1B9F7C69F93B0F1E10DE").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA99887766554433221109").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F1011121314151617").to_vec(),
                ciphertext: hex!("221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110A").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
                ciphertext: hex!("BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110B").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("FE80690BEE8A485D11F32965BC9D2A32").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110C").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").to_vec(),
                ciphertext: hex!("2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110D").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627").to_vec(),
                ciphertext: hex!("D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110E").to_vec(),
                associated_data: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627").to_vec(),
                plaintext: hex!("").to_vec(),
                ciphertext: hex!("C5CD9D1850C141E358649994EE701B68").to_vec(),
            },
            Kat {
                nonce: hex!("BBAA9988776655443322110F").to_vec(),
                associated_data: hex!("").to_vec(),
                plaintext: hex!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627").to_vec(),
                ciphertext: hex!("4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479").to_vec(),
            },
        ];

    for kat in kats {
        let ocb3 = Aes128Ocb3::new(&key);

        let buffer = &mut kat.plaintext.clone();
        let tag = ocb3
            .encrypt_in_place_detached(
                kat.nonce.as_slice().into(),
                kat.associated_data.as_slice(),
                buffer,
            )
            .unwrap();

        assert_eq!(
            &tag,
            Block::from_slice(&kat.ciphertext.as_slice()[kat.ciphertext.len() - 16..])
        );
        assert_eq!(
            buffer.as_slice(),
            &kat.ciphertext.as_slice()[..kat.ciphertext.len() - 16]
        );

        let res = ocb3.decrypt_in_place_detached(
            kat.nonce.as_slice().into(),
            kat.associated_data.as_slice(),
            buffer,
            &tag,
        );
        assert!(res.is_ok());
        assert_eq!(buffer.as_slice(), kat.plaintext.as_slice());
    }
}
