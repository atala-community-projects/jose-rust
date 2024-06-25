use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;
use serde_wasm_bindgen::from_value;

#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
export enum ENCAlgorithm {
    XC20P="XC20P",
    A256GCM="A256GCM",
    A256CBC_HS512="A256CBC-HS512"
}
export enum KWAlgorithm {
    ECDH_ES_A256KW="ECDH-ES+A256KW",
    ECDH_1PU_A256KW="ECDH-1PU+A256KW"
}
export type Recipient = [string, string];
export type Recipients = Recipient[];
export type ECDH_HEADER = {
    enc: string,
    alg: string,
    apv: string
}
export class ECDH{
    free(): void;
    constructor();
    static anonEncryptEc(
        recipients: Recipients,
        header: ECDH_HEADER,
        message: Uint8Array
    ): string
}
"#;

#[wasm_bindgen]
extern "C" {
    #[derive(Clone, Default)]
    pub type Key;

    #[wasm_bindgen(method, getter = raw)]
    pub fn raw(this: &Key) -> JsValue;
}


#[derive(Debug, PartialEq, Eq)]
#[wasm_bindgen]
pub struct ECDH { }


#[derive(Debug, PartialEq, Eq)]
#[wasm_bindgen(skip_typescript)]
pub struct EcdhHeader {
    pub(crate) enc: String,
    pub(crate) alg: String,
    pub(crate) apv: String
}

#[wasm_bindgen]
impl ECDH {

    #[wasm_bindgen(js_name="anonEncryptEC")]
    pub fn anon_encrypt_ec(recipients: JsValue, headers: JsValue, message: JsValue) -> Result<String, JsValue> {
        let recipients: Vec<(String, String)> = from_value(recipients).expect("Invalid Recipients");
        let headers: EcdhHeader = from_value(headers).expect("Invalid headers");
        let message: &[u8] = from_value(message).expect("Invalid message");
        todo!()
    }

    #[wasm_bindgen(js_name="anonDencryptEC")]
    pub fn anon_decrypt_ec() -> Result<String, JsValue> {
        todo!()
    }

    #[wasm_bindgen(js_name="authEncryptEC")]
    pub fn auth_encrypt_ec() -> Result<String, JsValue> {
        todo!()
    }

    #[wasm_bindgen(js_name="authDencryptEC")]
    pub fn auth_decrypt_ec() -> Result<String, JsValue> {
        todo!()
    }
}


/*    #[wasm_bindgen]
    pub fn encrypt(plain_text: String, pk_jwk: String, pk_kid: String, algorithm: ALG) -> Result<String, JsValue> {
        let bob_pkey = X25519KeyPair::from_jwk(pk_jwk.as_str()).expect("unable to extract key from jwk string");


        match algorithm {
            ALG::Ecdh1puA256kw => {
                let jwe_string =  jwe::encrypt::<
                    AesKey<A256CbcHs512>,
                    Ecdh1PU<'_, X25519KeyPair>,
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
            },
            ALG::EcdhEsA256kw => {
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
        }








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
    }*/