//! Tencent AIDL software test replies. No hardware or biometric authentication.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
    time::{Duration, Instant},
};

use pif_common::soter_blob as blob;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey};

use super::{BAD_VALUE, DESCRIPTOR, MAX_REQUEST_BYTES, UNKNOWN_TRANSACTION};

const NO_KEY: i32 = -5;
const NO_AUTH_KEY: i32 = -6;
const UNAVAILABLE: i32 = -20;
const NO_FINGERPRINT: i32 = -26;
const NO_SESSION: i32 = -1000;
const MAX_UIDS: usize = 1024;
const MAX_KEYS_PER_UID: usize = 64;
const MAX_SESSIONS: usize = 64;
const MAX_STRING_UNITS: usize = 16 * 1024;
const SESSION_LIFETIME: Duration = Duration::from_secs(120);

// Deliberately recognizable public software-test identity, never a factory ID.
const DEVICE: &[u8; 16] = &[
    0x00, 0x00, 0x00, 0x00, 0x72, 0x55, 0x90, 0xfc,
    0xa2, 0x0e, 0x90, 0x94, 0xa0, 0x70, 0x39, 0x1a,
];
const CPU_ID: &str = "00000000725590fca20e9094a070391a";

// PUBLIC, NON-SECRET test material from RustCrypto RSA 0.9.10:
// tests/examples/pkcs8/rsa2048-priv.pem (MIT OR Apache-2.0).
// Shared by every installation/UID/alias. Never use for authentication or secrets.
const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDefaO0kZ0HMDND
1mfHeYjL3bQ8oi6wf/vRDkJYRxUm0iYXmLq1arkkJfa43W8WtPa8bVUeZoDo/lN5
xm6YfLCnHGhVaCVP/mMlxrBJfgL1cehDS9hm5wEKmWe0evxtonEHcxOmTT00s89o
1wCX6B7o/wG530BxZ1YjXhaw2Ki6dJ4NFCsnKhfeFeQZmDJNguyF+eY6KUfOo8/f
ZcFmZn87MmeFJ2itXnlpfRYmsiAGmoU4kECNVHl8pxWpgbVJDSc9phblal+/rQQn
vQV+xC3EN/39Vx+6tNOvRvtWOtngDQ09LrkljsY+NBRKpkfDxzno3L7Obov5NgVY
oBWoh3xzAgMBAAECggEBAMN1EKoC+jZka8T+yHD/HeQrQrm5qNa5uJlxs2smFzjh
iUFVlUDnHvrYtyS0s3D5TYE/c3Wfi0QkmWTzpBkmAXLti+Lr+UuLKcL4B8qofyTt
CqSELvpHmiybk/WDzdrqx+1JdUu1sz1ncaCisQzCiNUboYKO1GhL5epwL/Lwg1o4
kMXEfRCgH58K9pEqSfhxpO84IuE48b8T9K5rElPa6tR4SuS4LXaDKpYckCt89K8j
R533Le7OVy4AD0ZpLdafSByf9jkLwqhAwT/5ZVlcrSZMd2Ot7c6B6OwYLzJok5UA
EyBWQRw0E0Tx5MhP3JpBkNALueoTzmATnNBHB60zogECgYEA4NKIQtP9veGbRMO5
gHHpBvxSj5muXsvDX9bsT0ZhVsO0+AyaDeLmhX3QW2uK/GKdyP6DwaSjQDBVW8G7
G0sd3QqCsVxkkWyFGurbDMPcUb72gphAcETHGOMs0H2Vzu2XB8H3Ulwp1nKr1Xe8
TeoAoMXFiZ/4W1pPg1cTiwiKr/MCgYEA/VhVBpUeI7m3pbF7FI6QS4kUaxVZ93G+
8GsUezovubDKda67W1kboXW9pr+cs9/IhYwyqh6gY74QF0UWRZ3wk3gDcxVjafot
FsZvbNUc689bjGpNigK9eG30/4kCf5IN+VBhzionFsJbw6pHiL3HuQvp0YvY6HSP
tYp5RVJPoYECgYEAkDzCCw3y1yWs9fsUQiHSvRaY6WRRiKP13sEGrv2aaY35xsJe
+9W8y5wiVuSyMKYcUN1pLo0v53ia6tlp72LL8ApUOvHp25rh8pkGnDP0X8XCZZrE
jMKzcXYeREyuFio8IVACGqbieKDtOXEuMFaWvI7l4xvsvL8+ECeHdEWwpJ0CgYEA
/I5zbLV5L1o0Bt0QeuTIWlTUYxAM+Q2OsHO/Hj1aWH4yxvCi3CTP07zhjHrWR8be
SqwB0e/oKqbNubToyAv0Sb7JiY+X5I0/J8Y4TEGDrFyxwiAzHlMu+QB8zcWTFQPQ
JGuKpREGmLy26C83Us0GbqW+uWP1n36byPm7fWzZ74ECgYA1RfUZyiq9RCGkt2FM
NeVFyyMcTVnpLSYcZr4qCsKfDE0dNjKbnD0rj9janmvk7Grf+mh6XmkF7tE/9MsF
qnx7N5Ex1flZCogJenj8TJb5RpZmpfPTWjGUlTK6ZZW8s29vxctt71+RhV4QBL9V
9hMQN0YpjO/BfsUF9Q9AYe1/Iw==
-----END PRIVATE KEY-----
";

struct Fixture {
    private: RsaPrivateKey,
    public_pem: String,
}

fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: OnceLock<Option<Fixture>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let mut private = RsaPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY).ok()?;
            private.validate().ok()?;
            private.precompute().ok()?;
            let public_pem = blob::public_key_pem(&RsaPublicKey::from(&private))?;
            Some(Fixture {
                private,
                public_pem,
            })
        })
        .as_ref()
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Option<&[u8]> {
        let end = self.position.checked_add(length)?;
        let value = self.bytes.get(self.position..end)?;
        self.position = end;
        Some(value)
    }

    fn int32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn int64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn uid(&mut self) -> Option<u32> {
        self.int32()?.try_into().ok()
    }

    fn string(&mut self) -> Option<Option<String>> {
        let length = self.int32()?;
        if length == -1 {
            return Some(None);
        }
        let length: usize = length.try_into().ok()?;
        if length > MAX_STRING_UNITS {
            return None;
        }
        let raw = self.take((length + 1).checked_mul(2)?)?;
        if raw.get(raw.len() - 2..)? != [0, 0] {
            return None;
        }
        let units = raw[..length * 2]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect::<Vec<_>>();
        let padding = (4 - self.position % 4) % 4;
        self.take(padding)?;
        Some(Some(String::from_utf16(&units).ok()?))
    }
}

fn arguments(bytes: &[u8]) -> Option<Reader<'_>> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return None;
    }
    // Standard Android Java header, and bounded legacy OEM header variants.
    // Never discover a descriptor by scanning arbitrary alias/challenge data.
    for position in [12, 8, 4, 0] {
        let mut reader = Reader { bytes, position };
        if reader.string().flatten().as_deref() == DESCRIPTOR.to_str().ok() {
            return Some(reader);
        }
    }
    None
}

pub(super) fn valid_request(code: u32, bytes: &[u8]) -> bool {
    (1..=13).contains(&code) && arguments(bytes).is_some()
}

enum Request {
    Uid(u32),
    Key(u32, Option<String>),
    Init(u32, Option<String>, Option<String>),
    Session(i64),
    None,
}

fn parse_request(code: u32, bytes: &[u8]) -> Result<Request, i32> {
    if !(1..=13).contains(&code) {
        return Err(UNKNOWN_TRANSACTION);
    }
    let mut reader = arguments(bytes).ok_or(BAD_VALUE)?;
    Ok(match code {
        1..=3 | 7 => Request::Uid(reader.uid().ok_or(BAD_VALUE)?),
        4..=6 | 8 => Request::Key(
            reader.uid().ok_or(BAD_VALUE)?,
            reader.string().ok_or(BAD_VALUE)?,
        ),
        9 => Request::Init(
            reader.uid().ok_or(BAD_VALUE)?,
            reader.string().ok_or(BAD_VALUE)?,
            reader.string().ok_or(BAD_VALUE)?,
        ),
        10 => Request::Session(reader.int64().ok_or(BAD_VALUE)?),
        13 => {
            reader.string().ok_or(BAD_VALUE)?;
            Request::None
        }
        _ => Request::None,
    })
}

#[derive(Default)]
struct UidState {
    ask: bool,
    keys: BTreeSet<String>,
    counter: u64,
}

struct Session {
    uid: u32,
    key: String,
    opened: Instant,
}

#[derive(Default)]
pub(super) struct SoftwareState {
    uids: BTreeMap<u32, UidState>,
    sessions: BTreeMap<i64, Session>,
    next_session: i64,
}

pub(super) trait Writer {
    fn int32(&mut self, value: i32) -> Result<(), i32>;
    fn int64(&mut self, value: i64) -> Result<(), i32>;
    fn bytes(&mut self, value: &[u8]) -> Result<(), i32>;
}

fn buffer_reply(output: &mut impl Writer, code: i32, data: &[u8]) -> Result<(), i32> {
    output.int32(1)?;
    output.int32(code)?;
    output.bytes(data)?;
    output.int32(data.len() as i32)
}

impl SoftwareState {
    fn generate_ask(&mut self, uid: u32) -> i32 {
        if !self.uids.contains_key(&uid) && self.uids.len() >= MAX_UIDS {
            return UNAVAILABLE;
        }
        self.uids.entry(uid).or_default().ask = true;
        0
    }

    fn has_ask(&self, uid: u32) -> bool {
        self.uids.get(&uid).is_some_and(|state| state.ask)
    }

    fn has_auth(&self, uid: u32, key: &str) -> bool {
        self.uids
            .get(&uid)
            .is_some_and(|state| state.ask && state.keys.contains(key))
    }

    fn key_code(&mut self, code: u32, uid: u32, key: Option<String>) -> i32 {
        let Some(key) = key.filter(|key| !key.is_empty()) else {
            return BAD_VALUE;
        };
        let Some(state) = self.uids.get_mut(&uid).filter(|state| state.ask) else {
            return NO_KEY;
        };
        if code == 4 {
            if !state.keys.contains(&key) && state.keys.len() >= MAX_KEYS_PER_UID {
                return UNAVAILABLE;
            }
            state.keys.insert(key);
            0
        } else if state.keys.remove(&key) {
            self.sessions
                .retain(|_, session| session.uid != uid || session.key != key);
            0
        } else {
            NO_AUTH_KEY
        }
    }

    fn export(&mut self, uid: u32, key: Option<&str>) -> Result<Vec<u8>, i32> {
        if !self.has_ask(uid) {
            return Err(NO_KEY);
        }
        if let Some(key) = key
            && !self.has_auth(uid, key)
        {
            return Err(NO_AUTH_KEY);
        }
        let fixture = fixture().ok_or(UNAVAILABLE)?;
        let state = self.uids.get_mut(&uid).ok_or(NO_KEY)?;
        let counter = state.counter.checked_add(1).ok_or(UNAVAILABLE)?;
        let mut value: serde_json::Value =
            serde_json::from_slice(&blob::key_json(&fixture.public_pem, CPU_ID, counter, uid))
                .map_err(|_| UNAVAILABLE)?;
        value["software_test"] = true.into();
        value["key_source"] = "public_test_fixture".into();
        if let Some(key) = key {
            value["key_name"] = key.into();
        }
        let json = serde_json::to_vec(&value).map_err(|_| UNAVAILABLE)?;
        let signature = blob::sign(&fixture.private, &json).ok_or(UNAVAILABLE)?;
        state.counter = counter;
        Ok(blob::encode(&json, &signature))
    }

    fn init(&mut self, uid: u32, key: Option<String>, challenge: Option<String>) -> (i32, i64) {
        let Some(key) = key.filter(|key| !key.is_empty()) else {
            return (BAD_VALUE, 0);
        };
        if challenge.is_none() {
            return (BAD_VALUE, 0);
        }
        if !self.has_auth(uid, &key) {
            return (NO_AUTH_KEY, 0);
        }
        self.sessions
            .retain(|_, session| session.opened.elapsed() < SESSION_LIFETIME);
        if self.sessions.len() >= MAX_SESSIONS {
            return (UNAVAILABLE, 0);
        }
        let Some(id) = self.next_session.checked_add(1) else {
            return (UNAVAILABLE, 0);
        };
        self.next_session = id;
        self.sessions.insert(
            id,
            Session {
                uid,
                key,
                opened: Instant::now(),
            },
        );
        (0, id)
    }

    fn finish(&mut self, id: i64) -> i32 {
        // This process has no trusted biometric evidence. Never sign challenges
        // or return invented TEE/fingerprint claims from the public test key.
        match self.sessions.remove(&id) {
            Some(session) if session.opened.elapsed() < SESSION_LIFETIME => NO_FINGERPRINT,
            _ => NO_SESSION,
        }
    }

    pub(super) fn write_reply(
        &mut self,
        code: u32,
        request: &[u8],
        output: &mut impl Writer,
    ) -> Result<(), i32> {
        let request = parse_request(code, request)?;
        output.int32(0)?; // Java Parcel.writeNoException()
        match (code, request) {
            (1, Request::Uid(uid)) => output.int32(self.generate_ask(uid)),
            (2, Request::Uid(uid)) => match self.export(uid, None) {
                Ok(bytes) => buffer_reply(output, 0, &bytes),
                Err(code) => buffer_reply(output, code, &[]),
            },
            (3, Request::Uid(uid)) => output.int32(i32::from(self.has_ask(uid))),
            (4 | 5, Request::Key(uid, key)) => output.int32(self.key_code(code, uid, key)),
            (6, Request::Key(uid, key)) => {
                let result = key
                    .filter(|key| !key.is_empty())
                    .ok_or(BAD_VALUE)
                    .and_then(|key| self.export(uid, Some(&key)));
                match result {
                    Ok(bytes) => buffer_reply(output, 0, &bytes),
                    Err(code) => buffer_reply(output, code, &[]),
                }
            }
            (7, Request::Uid(uid)) => {
                self.sessions.retain(|_, session| session.uid != uid);
                match self.uids.get_mut(&uid).filter(|state| state.ask) {
                    Some(state) => {
                        // Preserve the counter even after deletion/recreation.
                        state.ask = false;
                        state.keys.clear();
                        output.int32(0)
                    }
                    None => output.int32(NO_KEY),
                }
            }
            (8, Request::Key(uid, key)) => output.int32(i32::from(
                key.as_deref().is_some_and(|key| self.has_auth(uid, key)),
            )),
            (9, Request::Init(uid, key, challenge)) => {
                let (code, session) = self.init(uid, key, challenge);
                output.int32(1)?;
                output.int64(session)?;
                output.int32(code)
            }
            (10, Request::Session(id)) => buffer_reply(output, self.finish(id), &[]),
            (11, Request::None) => buffer_reply(output, 0, DEVICE),
            (12, Request::None) => output.int32(1),
            (13, Request::None) => {
                output.int32(1)?;
                output.int32(-1) // Parcel.writeValue(null), no biometric capability.
            }
            _ => Err(BAD_VALUE),
        }
    }
}
