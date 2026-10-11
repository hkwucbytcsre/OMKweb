//! RSA-2048 RSASSA-PSS signing for the forged Soter key exports.
//!
//! The reference ATTK signs ASK exports, and each ASK signs its AuthKey exports.
//! ASK and AuthKey subjects use independent runtime-generated RSA key pairs. The parameters mirror
//! the D-Soter reference implementation: SHA-256 with MGF1-SHA256, a 20-byte salt, and
//! `emBits = 2047` over a 2048-bit modulus.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use jni::{
    JNIEnv, JavaVM,
    objects::{JByteArray, JValue},
};
use num_bigint_dig::BigUint;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Reference ATTK public half used to verify ASK signatures in tests.
#[cfg(test)]
pub(crate) const ATTK_PUBLIC_B64: &str = concat!(
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3n2jtJGdBzAzQ9Znx3mI",
    "y920PKIusH/70Q5CWEcVJtImF5i6tWq5JCX2uN1vFrT2vG1VHmaA6P5TecZumHyw",
    "pxxoVWglT/5jJcawSX4C9XHoQ0vYZucBCplntHr8baJxB3MTpk09NLPPaNcAl+ge",
    "6P8Bud9AcWdWI14WsNiounSeDRQrJyoX3hXkGZgyTYLshfnmOilHzqPP32XBZmZ/",
    "OzJnhSdorV55aX0WJrIgBpqFOJBAjVR5fKcVqYG1SQ0nPaYW5Wpfv60EJ70FfsQt",
    "xDf9/VcfurTTr0b7VjrZ4A0NPS65JY7GPjQUSqZHw8c56Ny+zm6L+TYFWKAVqId8",
    "cwIDAQAB",
);

/// Reference ATTK private half. It signs ASK exports; ASK keys sign AuthKey exports.
const ATTK_PRIVATE_B64: &str = concat!(
    "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDefaO0kZ0HMDND",
    "1mfHeYjL3bQ8oi6wf/vRDkJYRxUm0iYXmLq1arkkJfa43W8WtPa8bVUeZoDo/lN5",
    "xm6YfLCnHGhVaCVP/mMlxrBJfgL1cehDS9hm5wEKmWe0evxtonEHcxOmTT00s89o",
    "1wCX6B7o/wG530BxZ1YjXhaw2Ki6dJ4NFCsnKhfeFeQZmDJNguyF+eY6KUfOo8/f",
    "ZcFmZn87MmeFJ2itXnlpfRYmsiAGmoU4kECNVHl8pxWpgbVJDSc9phblal+/rQQn",
    "vQV+xC3EN/39Vx+6tNOvRvtWOtngDQ09LrkljsY+NBRKpkfDxzno3L7Obov5NgVY",
    "oBWoh3xzAgMBAAECggEBAMN1EKoC+jZka8T+yHD/HeQrQrm5qNa5uJlxs2smFzjh",
    "iUFVlUDnHvrYtyS0s3D5TYE/c3Wfi0QkmWTzpBkmAXLti+Lr+UuLKcL4B8qofyTt",
    "CqSELvpHmiybk/WDzdrqx+1JdUu1sz1ncaCisQzCiNUboYKO1GhL5epwL/Lwg1o4",
    "kMXEfRCgH58K9pEqSfhxpO84IuE48b8T9K5rElPa6tR4SuS4LXaDKpYckCt89K8j",
    "R533Le7OVy4AD0ZpLdafSByf9jkLwqhAwT/5ZVlcrSZMd2Ot7c6B6OwYLzJok5UA",
    "EyBWQRw0E0Tx5MhP3JpBkNALueoTzmATnNBHB60zogECgYEA4NKIQtP9veGbRMO5",
    "gHHpBvxSj5muXsvDX9bsT0ZhVsO0+AyaDeLmhX3QW2uK/GKdyP6DwaSjQDBVW8G7",
    "G0sd3QqCsVxkkWyFGurbDMPcUb72gphAcETHGOMs0H2Vzu2XB8H3Ulwp1nKr1Xe8",
    "TeoAoMXFiZ/4W1pPg1cTiwiKr/MCgYEA/VhVBpUeI7m3pbF7FI6QS4kUaxVZ93G+",
    "8GsUezovubDKda67W1kboXW9pr+cs9/IhYwyqh6gY74QF0UWRZ3wk3gDcxVjafot",
    "FsZvbNUc689bjGpNigK9eG30/4kCf5IN+VBhzionFsJbw6pHiL3HuQvp0YvY6HSP",
    "tYp5RVJPoYECgYEAkDzCCw3y1yWs9fsUQiHSvRaY6WRRiKP13sEGrv2aaY35xsJe",
    "+9W8y5wiVuSyMKYcUN1pLo0v53ia6tlp72LL8ApUOvHp25rh8pkGnDP0X8XCZZrE",
    "jMKzcXYeREyuFio8IVACGqbieKDtOXEuMFaWvI7l4xvsvL8+ECeHdEWwpJ0CgYEA",
    "/I5zbLV5L1o0Bt0QeuTIWlTUYxAM+Q2OsHO/Hj1aWH4yxvCi3CTP07zhjHrWR8be",
    "SqwB0e/oKqbNubToyAv0Sb7JiY+X5I0/J8Y4TEGDrFyxwiAzHlMu+QB8zcWTFQPQ",
    "JGuKpREGmLy26C83Us0GbqW+uWP1n36byPm7fWzZ74ECgYA1RfUZyiq9RCGkt2FM",
    "NeVFyyMcTVnpLSYcZr4qCsKfDE0dNjKbnD0rj9janmvk7Grf+mh6XmkF7tE/9MsF",
    "qnx7N5Ex1flZCogJenj8TJb5RpZmpfPTWjGUlTK6ZZW8s29vxctt71+RhV4QBL9V",
    "9hMQN0YpjO/BfsUF9Q9AYe1/Iw==",
);

/// Only owned DER bytes cross the JNI local frame; Java objects are never cached.
pub(crate) struct KeyPair {
    pub(crate) public_der: Vec<u8>,
    pub(crate) private_der: Vec<u8>,
}

static VM: OnceLock<JavaVM> = OnceLock::new();

pub(crate) fn initialize_vm(env: &JNIEnv<'_>) -> bool {
    match env.get_java_vm() {
        Ok(vm) => VM.set(vm).is_ok() || VM.get().is_some(),
        Err(_) => false,
    }
}

/// Use Android's RSA provider, with no dependency on a platform libcrypto ABI.
pub(crate) fn generate_keypair() -> Option<KeyPair> {
    let mut env = VM.get()?.attach_current_thread().ok()?;
    // Do not clear an exception belonging to the caller.
    if env.exception_check().ok()? {
        return None;
    }
    let result = env.with_local_frame(16, |env| -> jni::errors::Result<KeyPair> {
        let algorithm = env.new_string("RSA")?;
        let generator = env
            .call_static_method(
                "java/security/KeyPairGenerator",
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[JValue::Object(algorithm.as_ref())],
            )?
            .l()?;
        env.call_method(&generator, "initialize", "(I)V", &[JValue::Int(2048)])?;
        let pair = env
            .call_method(
                &generator,
                "generateKeyPair",
                "()Ljava/security/KeyPair;",
                &[],
            )?
            .l()?;
        let public = env
            .call_method(&pair, "getPublic", "()Ljava/security/PublicKey;", &[])?
            .l()?;
        let private = env
            .call_method(&pair, "getPrivate", "()Ljava/security/PrivateKey;", &[])?
            .l()?;
        let public = JByteArray::from(env.call_method(public, "getEncoded", "()[B", &[])?.l()?);
        let private = JByteArray::from(env.call_method(private, "getEncoded", "()[B", &[])?.l()?);
        Ok(KeyPair {
            public_der: env.convert_byte_array(public)?,
            private_der: env.convert_byte_array(private)?,
        })
    });
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
    result
        .ok()
        .filter(|key| !key.public_der.is_empty() && !key.private_der.is_empty())
}

pub(crate) fn attk_private_der() -> Option<Vec<u8>> {
    BASE64.decode(ATTK_PRIVATE_B64).ok()
}

/// Real installs persist a monotonically increasing key counter, and the Soter client rejects a
/// key whose counter is not positive, so a freshly minted ASK always reports at least one.
pub(crate) const KEY_COUNTER: i64 = 1;

const MODULUS_BYTES: usize = 256;
const HASH_BYTES: usize = 32;
const SALT_BYTES: usize = 20;
const EM_BITS: usize = 2047;

/// Read one DER tag-length-value triple from `buffer`, advancing `offset`.
fn der_tlv<'a>(buffer: &'a [u8], offset: &mut usize) -> Option<(u8, &'a [u8])> {
    let tag = *buffer.get(*offset)?;
    let first = *buffer.get(*offset + 1)?;
    *offset += 2;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > size_of::<usize>() {
            return None;
        }
        let bytes = buffer.get(*offset..*offset + count)?;
        *offset += count;
        bytes.iter().try_fold(0usize, |value, byte| {
            value.checked_mul(256)?.checked_add(usize::from(*byte))
        })?
    };
    let value = buffer.get(*offset..*offset + length)?;
    *offset += length;
    Some((tag, value))
}

/// Parse a PKCS#8 RSAPrivateKey and return its modulus, public exponent and private exponent.
fn parse_pkcs8_private(der: &[u8]) -> Option<(BigUint, BigUint, BigUint)> {
    let mut offset = 0;
    let (outer_tag, outer) = der_tlv(der, &mut offset)?;
    if outer_tag != 0x30 || offset != der.len() {
        return None;
    }
    let mut inner = 0;
    let (_, _) = der_tlv(outer, &mut inner)?;
    let (algorithm_tag, _) = der_tlv(outer, &mut inner)?;
    if algorithm_tag != 0x30 {
        return None;
    }
    let (octet_tag, octets) = der_tlv(outer, &mut inner)?;
    if octet_tag != 0x04 {
        return None;
    }
    let mut key = 0;
    let (key_tag, sequence) = der_tlv(octets, &mut key)?;
    if key_tag != 0x30 || key != octets.len() {
        return None;
    }
    let mut field = 0;
    let (_, _) = der_tlv(sequence, &mut field)?;
    let read_integer = |field: &mut usize| -> Option<BigUint> {
        let (tag, bytes) = der_tlv(sequence, field)?;
        if tag != 0x02 || bytes.is_empty() {
            return None;
        }
        let stripped = bytes
            .iter()
            .skip_while(|byte| **byte == 0)
            .copied()
            .collect::<Vec<_>>();
        (!stripped.is_empty()).then(|| BigUint::from_bytes_be(&stripped))
    };
    let modulus = read_integer(&mut field)?;
    let public = read_integer(&mut field)?;
    let private = read_integer(&mut field)?;
    Some((modulus, public, private))
}

/// MGF1 with SHA-256, as used by RSASSA-PSS.
fn mgf1(seed: &[u8], length: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(length + HASH_BYTES);
    let mut counter = 0u32;
    while mask.len() < length {
        let mut hash = Sha256::new();
        hash.update(seed);
        hash.update(counter.to_be_bytes());
        mask.extend_from_slice(&hash.finalize());
        counter += 1;
    }
    mask.truncate(length);
    mask
}

/// Sample a fresh PSS salt. A failure here leaves the export blob unsigned, which the caller logs.
fn random_salt() -> Option<[u8; SALT_BYTES]> {
    let mut salt = [0u8; SALT_BYTES];
    let mut file = std::fs::File::open("/dev/urandom").ok()?;
    std::io::Read::read_exact(&mut file, &mut salt).ok()?;
    Some(salt)
}

/// RSASSA-PSS encode the SHA-256 of `message_hash` with `salt`.
fn encode_pss(message_hash: &[u8], salt: &[u8; SALT_BYTES]) -> Option<Vec<u8>> {
    if message_hash.len() != HASH_BYTES {
        return None;
    }
    let mut hash_input = Vec::with_capacity(8 + HASH_BYTES + SALT_BYTES);
    hash_input.extend_from_slice(&[0u8; 8]);
    hash_input.extend_from_slice(message_hash);
    hash_input.extend_from_slice(salt);
    let hash = Sha256::digest(&hash_input);

    let mut block = Vec::with_capacity(MODULUS_BYTES);
    block.resize(MODULUS_BYTES - SALT_BYTES - HASH_BYTES - 2, 0);
    block.push(0x01);
    block.extend_from_slice(salt);

    let mask = mgf1(&hash, MODULUS_BYTES - HASH_BYTES - 1);
    for (byte, mask_byte) in block.iter_mut().zip(mask) {
        *byte ^= mask_byte;
    }
    let unused_bits = 8 * MODULUS_BYTES - EM_BITS;
    *block.first_mut()? &= 0xFF >> unused_bits;

    block.extend_from_slice(&hash);
    block.push(0xbc);
    Some(block)
}

/// Sign the exact bytes of an export JSON, mirroring the D-Soter reference parameters.
pub(crate) fn sign_export_json(private_der: &[u8], json: &[u8]) -> Option<[u8; MODULUS_BYTES]> {
    let salt = random_salt()?;
    sign_export_json_with_salt(private_der, json, &salt)
}

fn sign_export_json_with_salt(
    private_der: &[u8],
    json: &[u8],
    salt: &[u8; SALT_BYTES],
) -> Option<[u8; MODULUS_BYTES]> {
    let (modulus, _, private) = parse_pkcs8_private(private_der)?;
    if modulus.bits() != MODULUS_BYTES * 8 {
        return None;
    }
    let encoded = encode_pss(&Sha256::digest(json), salt)?;
    let signature = BigUint::from_bytes_be(&encoded).modpow(&private, &modulus);
    let bytes = signature.to_bytes_be();
    if bytes.len() > MODULUS_BYTES {
        return None;
    }
    let mut out = [0u8; MODULUS_BYTES];
    out[MODULUS_BYTES - bytes.len()..].copy_from_slice(&bytes);
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Fixed-salt signature over a fixed export JSON, produced by the D-Soter C++ reference
    /// implementation (`soter_attk.h`, salt forced to `0x11 * (index + 1)`). Any change to the
    /// key pair, the JSON layout, the hash, the mask generation, `emBits`, or the salt length
    /// breaks this test.
    const KNOWN_JSON: &str = concat!(
        "{\"pub_key\":\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3n2jtJGdBzAzQ9Znx3mI",
        "y920PKIusH/70Q5CWEcVJtImF5i6tWq5JCX2uN1vFrT2vG1VHmaA6P5TecZumHyw",
        "pxxoVWglT/5jJcawSX4C9XHoQ0vYZucBCplntHr8baJxB3MTpk09NLPPaNcAl+ge",
        "6P8Bud9AcWdWI14WsNiounSeDRQrJyoX3hXkGZgyTYLshfnmOilHzqPP32XBZmZ/",
        "OzJnhSdorV55aX0WJrIgBpqFOJBAjVR5fKcVqYG1SQ0nPaYW5Wpfv60EJ70FfsQt",
        "xDf9/VcfurTTr0b7VjrZ4A0NPS65JY7GPjQUSqZHw8c56Ny+zm6L+TYFWKAVqId8",
        "cwIDAQAB\",\"counter\":1,\"cpu_id\":\"00000000725590fca20e9094a070391a\",\"uid\":10123}",
    );
    const KNOWN_SIGNATURE: &str = concat!(
        "29f3fb31d6c0b2e08aa463e39e77ec5d55f9eecc9d28f8bfdaa414c6cf0a3339",
        "5a057a63eebfd30730f3daf9d374555636f06d02b7776f75b4b7c8b677bc03db",
        "b203631b61082af859cafbe1f8d1185eaa6400c8f501587d9792e51009d2c54c",
        "f1044899bb91f3a8d26854849ec4f2425f7804e73fb057d5b56c345678c06c95",
        "d630b3219e793341ebd1eae3c365bf3e78b9eb6a0ebaa8fb9fc400a073e10a6c",
        "c54344cf6d9dd081fcd32b04c51d0f234d716cb31ea184d644d60dd609054c55",
        "f0863a8d8f438eadac15e5626fc2ee5c76e5d62193b0d1b26e551b4efb2ed003",
        "76a701f9e859fba6d6914cc45b4c72c7db768525d8e796582911ccb3587149b8",
    );

    #[test]
    fn matches_the_reference_implementation_byte_for_byte() {
        let salt = std::array::from_fn(|index| (0x11u32 * (index as u32 + 1)) as u8);
        let signature =
            sign_export_json_with_salt(&attk_private_der().unwrap(), KNOWN_JSON.as_bytes(), &salt)
                .unwrap();
        assert_eq!(hex(&signature), KNOWN_SIGNATURE);
    }

    #[test]
    fn embedded_pair_is_consistent_and_signs_new_salts() {
        let der = BASE64.decode(ATTK_PRIVATE_B64).unwrap();
        let (modulus, public, _) = parse_pkcs8_private(&der).unwrap();
        assert_eq!(modulus.bits(), MODULUS_BYTES * 8);
        let signature = sign_export_json(&der, KNOWN_JSON.as_bytes()).unwrap();
        assert!(verifies(
            &signature,
            KNOWN_JSON.as_bytes(),
            &modulus,
            &public
        ));
    }

    #[test]
    fn rejects_a_different_message() {
        let der = BASE64.decode(ATTK_PRIVATE_B64).unwrap();
        let (modulus, public, _) = parse_pkcs8_private(&der).unwrap();
        let signature = sign_export_json(&der, KNOWN_JSON.as_bytes()).unwrap();
        assert!(!verifies(&signature, b"{}", &modulus, &public));
    }

    pub(crate) fn verifies_export(blob: &[u8], private_der: &[u8]) -> bool {
        let length = u32::from_le_bytes(blob[..4].try_into().unwrap()) as usize;
        let json = &blob[4..4 + length];
        let signature = blob[4 + length..].try_into().unwrap();
        let (modulus, public, _) = parse_pkcs8_private(private_der).unwrap();
        verifies(signature, json, &modulus, &public)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Textbook RSASSA-PSS verification, used only to prove the embedded pair is self-consistent.
    pub(crate) fn verifies(
        signature: &[u8; MODULUS_BYTES],
        json: &[u8],
        modulus: &BigUint,
        public: &BigUint,
    ) -> bool {
        let message = BigUint::from_bytes_be(signature)
            .modpow(public, modulus)
            .to_bytes_be();
        if message.len() > MODULUS_BYTES {
            return false;
        }
        let mut encoded = vec![0u8; MODULUS_BYTES - message.len()];
        encoded.extend_from_slice(&message);
        if encoded.last() != Some(&0xbc) {
            return false;
        }
        let hash = &encoded[MODULUS_BYTES - HASH_BYTES - 1..MODULUS_BYTES - 1];
        let mask = mgf1(hash, MODULUS_BYTES - HASH_BYTES - 1);
        let mut block = encoded[..MODULUS_BYTES - HASH_BYTES - 1]
            .iter()
            .zip(mask)
            .map(|(byte, mask_byte)| byte ^ mask_byte)
            .collect::<Vec<_>>();
        block[0] &= 0xFF >> (8 * MODULUS_BYTES - EM_BITS);
        let separator = block.iter().position(|byte| *byte == 0x01);
        let Some(separator) = separator else {
            return false;
        };
        if block[..separator].iter().any(|byte| *byte != 0) {
            return false;
        }
        let salt = &block[separator + 1..];
        if salt.len() != SALT_BYTES {
            return false;
        }
        let mut hash_input = Vec::with_capacity(8 + HASH_BYTES + SALT_BYTES);
        hash_input.extend_from_slice(&[0u8; 8]);
        hash_input.extend_from_slice(&Sha256::digest(json));
        hash_input.extend_from_slice(salt);
        Sha256::digest(&hash_input)[..] == hash[..]
    }
}
