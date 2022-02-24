use super::{Deserialize, Deserializer, Result, Serialize, Serializer};

pub use lorawan_encoding::{
    default_crypto::DefaultFactory,
    keys,
    maccommands::{MacCommand, MacCommandIterator},
    parser::{
        parse as lorawan_parser, AsPhyPayloadBytes, DataHeader, DataPayload, EncryptedDataPayload,
        EncryptedJoinAcceptPayload, FRMPayload, JoinRequestPayload, PhyPayload,
    },
};

pub use semtech_udp::{parser::Parser, DataRate, Down, Packet, Up};

#[derive(PartialEq, Clone)]
pub struct DevAddr([u8; 4]);

impl DevAddr {
    pub fn copy_from_parser<T: std::convert::AsRef<[u8]>>(
        src: &lorawan_encoding::parser::DevAddr<T>,
    ) -> DevAddr {
        let mut dst = [0u8; 4];
        for (d, s) in dst.iter_mut().zip(src.as_ref().iter()) {
            *d = *s;
        }
        DevAddr(dst)
    }
}

pub struct Session {
    pub newskey: keys::AES128,
    pub appskey: keys::AES128,
    pub devaddr: DevAddr,
}

pub struct Device {
    pub credentials: Credentials,
    pub last_join_request: Option<JoinRequestPayload<Vec<u8>, DefaultFactory>>,
    pub session: Option<Session>,
}

impl Device {
    pub fn new(credentials: Credentials) -> Device {
        Device {
            credentials,
            last_join_request: None,
            session: None,
        }
    }
}

pub enum Pkt<'a> {
    Up(&'a semtech_udp::push_data::RxPk),
    Down(&'a semtech_udp::pull_resp::TxPk),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SniffedPacket {
    pub tmst: u32,
    #[serde(
        serialize_with = "serialize_payload",
        deserialize_with = "deserialize_payload"
    )]
    pub payload: PhyPayload<Vec<u8>, DefaultFactory>,
    pub freq: f64,
    pub datr: DataRate,
    pub direction: Direction,
    pub lsnr: Option<f32>,
    pub rssi: Option<i32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Direction {
    Up,
    Down,
}

impl SniffedPacket {
    pub fn new(pkt: Pkt) -> Result<SniffedPacket> {
        let tmst = match pkt {
            Pkt::Up(rxpk) => *rxpk.get_timestamp(),
            Pkt::Down(txpk) => match txpk.tmst {
                semtech_udp::StringOrNum::S(_) => 0,
                semtech_udp::StringOrNum::N(n) => n,
            },
        };
        let bytes = match pkt {
            Pkt::Up(rxpk) => rxpk.get_data().clone(),
            Pkt::Down(txpk) => txpk.data.clone(),
        };

        let (datr, freq, direction, lsnr, rssi) = match pkt {
            Pkt::Up(rxpk) => (
                rxpk.get_datarate(),
                *rxpk.get_frequency(),
                Direction::Up,
                Some(rxpk.get_snr()),
                Some(if let Some(rssi) = rxpk.get_signal_rssi() {
                    rssi
                } else {
                    rxpk.get_channel_rssi()
                }),
            ),
            Pkt::Down(txpk) => (txpk.datr.clone(), txpk.freq, Direction::Down, None, None),
        };

        Ok(SniffedPacket {
            payload: lorawan_parser(bytes)?,
            freq,
            datr,
            direction,
            tmst,
            lsnr,
            rssi,
        })
    }

    pub fn payload(&self) -> &PhyPayload<Vec<u8>, DefaultFactory> {
        &self.payload
    }
}

use std::fs;
use std::path::Path;

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Credentials {
    pub app_eui: String,
    pub app_key: String,
    pub dev_eui: String,
}

pub fn load_credentials(path: &str) -> Result<Option<Vec<Credentials>>> {
    if !Path::new(path).exists() {
        println!("No lorawan-devices.json found");
        return Ok(None);
    }

    let contents = fs::read_to_string(path)?;
    let devices: Vec<Credentials> = serde_json::from_str(&contents)?;
    Ok(Some(devices))
}

fn serialize_payload<S>(
    payload: &PhyPayload<Vec<u8>, DefaultFactory>,
    s: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let base64 = base64::encode(payload.as_ref());
    s.serialize_str(&base64)
}

fn deserialize_payload<'de, D>(
    deserializer: D,
) -> std::result::Result<PhyPayload<Vec<u8>, DefaultFactory>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(deserializer).unwrap();
    Ok(lorawan_encoding::parser::parse(base64::decode(s).unwrap()).unwrap())
}
