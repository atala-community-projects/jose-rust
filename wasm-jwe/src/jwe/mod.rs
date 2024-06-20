use std::error::Error;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

use didcomm::jwe::envelope::{Algorithm, EncAlgorithm, JWE as DIDCOMMJWE, PerRecipientHeader, Recipient};
use askar_crypto::{alg::{
    aes::{A256CbcHs512, A256Kw, AesKey},
    x25519::X25519KeyPair,
}};
use askar_crypto::jwk::FromJwk;
use askar_crypto::kdf::ecdh_es::EcdhEs;
use didcomm::error::ErrorKind;
use didcomm::jwe;

#[derive(Debug, PartialEq, Eq)]
#[wasm_bindgen]
pub struct JWE { }


#[wasm_bindgen]
impl JWE {

    #[wasm_bindgen]
    pub fn encrypt(plain_text: String, pk_jwk: String, pk_kid: String) -> Result<String, JsValue> {
        let bob_pkey = X25519KeyPair::from_jwk(pk_jwk.as_str())
            .expect("unable from_jwk");

        let jwe_string =  jwe::encrypt::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            plain_text.as_bytes(),
            Algorithm::EcdhEsA256kw,
            EncAlgorithm::A256cbcHs512,
            None,
            &[(pk_kid.as_str(), &bob_pkey)],
        ).map_err(|e| {
            JsValue::from("Error")
        })?;

        let jwe =  DIDCOMMJWE::from_str(&jwe_string).map_err(|e| {
            JsValue::from("Error")
        })?;

        let protected = jwe.protected;
        let enc_key = jwe.recipients.first().unwrap().encrypted_key;
        let iv = jwe.iv;
        let ciphertext = jwe.ciphertext;
        let tag =jwe.tag;

        Ok(
            format!("{protected}.{enc_key}.{iv}.{ciphertext}.{tag}")
        )
    }

    #[wasm_bindgen]
    pub fn decrypt(
        jwe_string: String,
        kid: String,
        sk_jwk: String
    ) -> Result<Vec<u8>, JsValue> {

        let mut buf = vec![];
        let mut recipients: Vec<Recipient> = Vec::new();
        let mut split = jwe_string.split(".")
            .map(|s| s.to_string())
            .collect::<Vec<String>>();

        //We split the JWE string by .
        // On index 1, the enc_key
        // We add a Vec<Recipient<'a>>, which contain only encrypted_key set
        recipients.push(Recipient {
            header: PerRecipientHeader {
                kid: kid.as_str()
            },
            encrypted_key: split.get(1).ok_or(ErrorKind::IllegalArgument).map_err(|e| {
                JsValue::from(e.source().unwrap().to_string())
            })?
        });

        let protected = split.get(0).ok_or(ErrorKind::IllegalArgument).map_err(|e| {
            JsValue::from(e.source().unwrap().to_string())
        })?;
        let iv =  split.get(2).ok_or(ErrorKind::IllegalArgument).map_err(|e| {
            JsValue::from(e.source().unwrap().to_string())
        })?;
        let ciphertext =  split.get(3).ok_or(ErrorKind::IllegalArgument).map_err(|e| {
            JsValue::from(e.source().unwrap().to_string())
        })?;
        let tag =  split.get(4).ok_or(ErrorKind::IllegalArgument).map_err(|e| {
            JsValue::from(e.source().unwrap().to_string())
        })?;

        let instance = DIDCOMMJWE {
            protected,
            recipients,
            iv,
            ciphertext,
            tag,
        };

        let jwe_json = serde_json::to_string(&instance).map_err(|e| {
            JsValue::from(e.source().unwrap().to_string())
        })?;

        let jwe = jwe::parse(jwe_json.as_str(), &mut buf).map_err(|e| {
            JsValue::from(e.source().unwrap().to_string())
        })?;
        let bob_pkey = X25519KeyPair::from_jwk(sk_jwk.as_str()).map_err(|e| {
            JsValue::from(e.source().unwrap().to_string())
        })?;
        let decrypted =  jwe.decrypt::<
            AesKey<A256CbcHs512>,
            EcdhEs<'_, X25519KeyPair>,
            X25519KeyPair,
            AesKey<A256Kw>,
        >(
            None,
            (kid.as_str(), &bob_pkey)
        ).map_err(|e| {
            JsValue::from(e.source.to_string())
        });

        decrypted
    }
}