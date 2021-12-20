use chrono::Utc;
use lorawan_encoding::{
    default_crypto::DefaultFactory,
    keys,
    parser::{
        parse as lorawan_parser, AsPhyPayloadBytes, DataHeader, DataPayload, EncryptedDataPayload,
        EncryptedJoinAcceptPayload, FRMPayload, JoinRequestPayload, PhyPayload,
    },
};
use mio::{
    net::UdpSocket,
    {Events, Poll, PollOpt, Ready, Token},
};
use semtech_udp::{parser::Parser, DataRate, Down, Packet, Up};
use serde_derive::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::{process, time::Duration};
use structopt::StructOpt;

const MINER: Token = Token(0);
const RADIO: Token = Token(1);

const DEVICES_PATH: &str = "lorawan-devices.json";
const CONFIG_PATH: &str = ".helium-console-config.toml";

#[derive(Debug, StructOpt)]
#[structopt(name = "lorawan-sniffer", about = "lorawan sniffing utility")]
struct Opt {
    /// IP address and port of miner mirror port
    /// (eg: 192.168.1.30:1681)
    #[structopt(short, long)]
    host: Option<String>,

    /// Optional API Key to populate devices from console
    #[structopt(short, long)]
    console: bool,

    /// disable timestamp on output
    #[structopt(long)]
    disable_ts: bool,

    /// enable tmst on output
    #[structopt(long)]
    enable_tmst: bool,

    /// enable raw payload output
    #[structopt(long)]
    enable_raw_payload: bool,

    /// Outgoing socket
    #[structopt(short, long, default_value = "3400")]
    out_port: u16,

    /// Incoming socket
    #[structopt(short, long, default_value = "1600")]
    in_port: u16,

    /// Output all frames
    #[structopt(short, long)]
    debug: bool,
}

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(PartialEq)]
struct DevAddr([u8; 4]);

impl DevAddr {
    fn copy_from_parser<T: std::convert::AsRef<[u8]>>(
        src: &lorawan_encoding::parser::DevAddr<T>,
    ) -> DevAddr {
        let mut dst = [0u8; 4];
        for (d, s) in dst.iter_mut().zip(src.as_ref().iter()) {
            *d = *s;
        }
        DevAddr(dst)
    }
}

struct Session {
    newskey: keys::AES128,
    appskey: keys::AES128,
    devaddr: DevAddr,
}

struct Device {
    credentials: Credentials,
    last_join_request: Option<JoinRequestPayload<Vec<u8>, DefaultFactory>>,
    session: Option<Session>,
}

impl Device {
    fn new(credentials: Credentials) -> Device {
        Device {
            credentials,
            last_join_request: None,
            session: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result {
    let cli = Opt::from_args();
    if let Err(e) = run(cli).await {
        println!("error: {}", e);
        process::exit(1);
    }
    Ok(())
}

mod config;

enum Pkt<'a> {
    Up(&'a semtech_udp::push_data::RxPk),
    Down(&'a semtech_udp::pull_resp::TxPk),
}

struct SniffedPacket {
    tmst: u32,
    payload: PhyPayload<Vec<u8>, DefaultFactory>,
    freq: f64,
    datr: DataRate,
    direction: Direction,
}

enum Direction {
    Up(RxRf),
    Down,
}

struct RxRf {
    lsnr: f32,
    rssi: i32,
}

impl SniffedPacket {
    fn new(pkt: Pkt) -> Result<SniffedPacket> {
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

        let (datr, freq, direction) = match pkt {
            Pkt::Up(rxpk) => (
                rxpk.get_datarate(),
                *rxpk.get_frequency(),
                Direction::Up(RxRf {
                    lsnr: rxpk.get_snr(),
                    rssi: if let Some(rssi) = rxpk.get_signal_rssi() {
                        rssi
                    } else {
                        rxpk.get_channel_rssi()
                    },
                }),
            ),
            Pkt::Down(txpk) => (txpk.datr.clone(), txpk.freq, Direction::Down),
        };

        Ok(SniffedPacket {
            payload: lorawan_parser(bytes)?,
            freq,
            datr,
            direction,
            tmst,
        })
    }

    fn payload(&self) -> &PhyPayload<Vec<u8>, DefaultFactory> {
        &self.payload
    }
}

use num_format::{Locale, ToFormattedString};

async fn run(opt: Opt) -> Result {
    // try to parse the CLI iput
    let mut miner_socket = if let Some(host) = opt.host {
        let miner_server = host.parse()?;
        let socket_addr = SocketAddr::from(([0, 0, 0, 0], opt.out_port));
        let socket = UdpSocket::bind(&socket_addr)?;
        // "connecting" filters for only frames from the server
        socket.connect(miner_server)?;
        // send something so that server can know about us
        socket.send(&[0])?;
        println!("Connected");

        Some(socket)
    } else {
        None
    };

    let mut devices = {
        let mut ret = Vec::new();

        if opt.console {
            let config = config::load(CONFIG_PATH)?;
            let client = helium_console::client::Client::new(config)?;
            let devices = client.get_devices().await?;
            for console_device in devices {
                let credentials = Credentials::from_console_device(console_device);
                ret.push(Device::new(credentials))
            }
        } else {
            let creds = load_credentials(DEVICES_PATH)?;
            if let Some(creds) = creds {
                for credentials in creds {
                    ret.push(Device::new(credentials))
                }
            }
        }
        ret
    };

    // we in turn put up our own server for the radio to connect to
    let radio_server = SocketAddr::from(([0, 0, 0, 0], opt.in_port));
    let radio_socket = UdpSocket::bind(&radio_server)?;
    println!("Server Up: {:?}", radio_socket);
    // setup the epoll events
    let poll = Poll::new()?;
    if let Some(socket) = &mut miner_socket {
        poll.register(socket, MINER, Ready::readable(), PollOpt::level())?;
    }
    poll.register(&radio_socket, RADIO, Ready::readable(), PollOpt::level())?;

    let mut buffer = [0; 1024];
    let mut events = Events::with_capacity(128);
    // we will stash the client address here when we see it
    // warning: this approach only supports a single radio client
    let mut radio_client = None;

    loop {
        poll.poll(&mut events, Some(Duration::from_millis(100)))?;

        for event in events.iter() {
            // handle the UDP events and collect packets for processing
            let mut packets: Vec<SniffedPacket> = Vec::new();
            match event.token() {
                MINER => {
                    if let Some(socket) = &mut miner_socket {
                        let num_recv = socket.recv(&mut buffer)?;
                        // forward the packet along
                        if let Some(radio_client) = &radio_client {
                            radio_socket.send_to(&buffer[0..num_recv], radio_client)?;
                        }
                        if let Ok(msg) = semtech_udp::Packet::parse(&buffer[..num_recv]) {
                            if opt.debug {
                                println!("{:?}", msg);
                            }
                            if let Packet::Up(Up::PushData(push_data)) = msg {
                                if let Some(rxpks) = &push_data.data.rxpk {
                                    for rxpk in rxpks {
                                        match SniffedPacket::new(Pkt::Up(rxpk)) {
                                            Ok(packet) => packets.push(packet),
                                            Err(e) => {
                                                if !opt.disable_ts {
                                                    print!(
                                                        "{}  ",
                                                        Utc::now().format("[%F %H:%M:%S%.3f]\t")
                                                    );
                                                }
                                                println!(
                                                    "SnifferPacket error: {}, with bytes: {:?}",
                                                    e,
                                                    base64::decode(&rxpk.get_data())
                                                );
                                            }
                                        }
                                    }
                                }
                            } else if let Packet::Down(Down::PullResp(pull_resp)) = msg {
                                match SniffedPacket::new(Pkt::Down(&pull_resp.data.txpk)) {
                                    Ok(packet) => packets.push(packet),
                                    Err(e) => {
                                        if !opt.disable_ts {
                                            print!(
                                                "{}  ",
                                                Utc::now().format("[%F %H:%M:%S%.3f]\t")
                                            );
                                        }
                                        println!(
                                            "SnifferPacket error: {}, with bytes: {:?}",
                                            e,
                                            base64::decode(&pull_resp.data.txpk.data)
                                        );
                                    }
                                }
                            }
                        } else {
                            println!("Received frame that is not a valid Semtech UDP frame");
                        }
                        buffer = [0; 1024];
                    }
                }
                RADIO => {
                    let (num_recv, src) = radio_socket.recv_from(&mut buffer)?;
                    radio_client = Some(src);
                    if let Some(socket) = &mut miner_socket {
                        socket.send(&buffer[0..num_recv])?;
                    }
                    let msg = semtech_udp::Packet::parse(&buffer[..num_recv])?;
                    if opt.debug {
                        println!("{:?}", msg);
                    }
                    buffer = [0; 1024];
                    if let Packet::Up(Up::PushData(push_data)) = msg {
                        if let Some(rxpks) = &push_data.data.rxpk {
                            for rxpk in rxpks {
                                packets.push(SniffedPacket::new(Pkt::Up(rxpk))?)
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }

            // process all the packets, including tracking Join/JoinAccept,
            // deriving session keys, and decrypting packets when possible
            for packet in packets {
                if !opt.disable_ts {
                    print!("{}  ", Utc::now().format("[%F %H:%M:%S%.3f]"));
                }

                print!(
                    "{}\t{:.1} MHz \t{:?}",
                    match &packet.payload() {
                        PhyPayload::JoinRequest(_) => "JoinRequest",
                        PhyPayload::JoinAccept(_) => "JoinAccept",
                        PhyPayload::Data(data) => {
                            if data.is_uplink() {
                                "DataUp"
                            } else {
                                "DataDown"
                            }
                        }
                    },
                    packet.freq,
                    packet.datr
                );

                match &packet.direction {
                    Direction::Up(data) => println!("\tRSSI: {:}\tLSNR: {:}", data.rssi, data.lsnr),
                    Direction::Down => println!(),
                }

                if opt.enable_tmst {
                    println!("\ttmst: {}", packet.tmst.to_formatted_string(&Locale::en));
                }

                match &packet.payload() {
                    PhyPayload::JoinRequest(join_request) => {
                        if opt.enable_raw_payload {
                            println!("\tPhyPayload: {:?} ", join_request.as_bytes())
                        }

                        println!(
                            "\t  AppEui: {:} DevEui: {:} DevNonce: {:}",
                            hex_encode_reversed(join_request.app_eui().as_ref()),
                            hex_encode_reversed(join_request.dev_eui().as_ref()),
                            hex_encode_reversed(join_request.dev_nonce().as_ref())
                        );

                        for device in &mut devices {
                            // compare bytes to hex string representation of bytes, flipped MSB
                            if compare_bth_flipped(
                                join_request.app_eui().as_ref(),
                                &device.credentials.app_eui,
                            )? && compare_bth_flipped(
                                join_request.dev_eui().as_ref(),
                                &device.credentials.dev_eui,
                            )? {
                                let mut copy: Vec<u8> = Vec::new();
                                copy.extend(join_request.as_bytes());
                                device.last_join_request = Some(JoinRequestPayload::new(copy)?);
                            }
                        }
                    }
                    PhyPayload::JoinAccept(join_accept) => {
                        if opt.enable_raw_payload {
                            println!("\tPhyPayload: {:?} ", join_accept.as_bytes())
                        }

                        for device in &mut devices {
                            let app_key = key_as_string_to_aes128(&device.credentials.app_key)?;
                            let mut copy: Vec<u8> = Vec::new();
                            copy.extend(join_accept.as_bytes());
                            let encrypted_join_accept = EncryptedJoinAcceptPayload::new(copy)?;
                            let decrypted_join_accept = encrypted_join_accept.decrypt(&app_key);

                            // If the MIC works, then we have matched a previous join request
                            // join response and we can now derive and save session keys
                            if decrypted_join_accept.validate_mic(&app_key) {
                                println!(
                                    "\tAppNonce: {:} NetId: {:} DevAddr: {:}",
                                    hex_encode_reversed(decrypted_join_accept.app_nonce().as_ref()),
                                    hex_encode_reversed(decrypted_join_accept.net_id().as_ref()),
                                    hex_encode_reversed(decrypted_join_accept.dev_addr().as_ref()),
                                );
                                println!(
                                    "\tDL Settings: {:x?} RxDelay: {:x?}, CFList: {:x?}",
                                    decrypted_join_accept.dl_settings(),
                                    decrypted_join_accept.rx_delay(),
                                    decrypted_join_accept.c_f_list(),
                                );

                                if let Some(join_request) = &device.last_join_request {
                                    let newskey = decrypted_join_accept
                                        .derive_newskey(&join_request.dev_nonce(), &app_key);

                                    let appskey = decrypted_join_accept
                                        .derive_appskey(&join_request.dev_nonce(), &app_key);

                                    println!("\tNewskey: {:X?}", newskey);
                                    println!("\tAppskey: {:X?}", appskey);

                                    device.session = Some(Session {
                                        newskey,
                                        appskey,
                                        devaddr: DevAddr::copy_from_parser(
                                            &decrypted_join_accept.dev_addr(),
                                        ),
                                    });
                                }
                                break;
                            }
                        }
                    }
                    PhyPayload::Data(data) => {
                        if opt.enable_raw_payload {
                            println!("\tPhyPayload: {:?} ", data.as_bytes())
                        }

                        match data {
                            DataPayload::Encrypted(encrypted_data) => {
                                let fport = match encrypted_data.f_port() {
                                    Some(fport) => format!("FPort {}", fport),
                                    None => "No FPort".to_string(),
                                };
                                let fhdr = encrypted_data.fhdr();

                                println!(
                                    "\tDevAddr: {:}, {:?}, FCnt x{:x?}, {}",
                                    hex_encode_reversed(fhdr.dev_addr().as_ref()),
                                    fhdr.fctrl(),
                                    fhdr.fcnt(),
                                    fport
                                );

                                let devaddr = DevAddr::copy_from_parser(&fhdr.dev_addr());

                                // fopts is a lazy iterator, so we need some boolean logic
                                let mut fopts = false;
                                for mac_cmd in fhdr.fopts() {
                                    if !fopts {
                                        print!("\t");
                                        fopts = true;
                                    }
                                    print!("{:x?}\t", mac_cmd);
                                }
                                if fopts {
                                    println!();
                                }

                                for (index, device) in devices.iter().enumerate() {
                                    // if there is a live session, check for address match
                                    if let Some(session) = &device.session {
                                        if session.devaddr == devaddr {
                                            if encrypted_data
                                                .validate_mic(&session.newskey, fhdr.fcnt() as u32)
                                            {
                                                let mut copy: Vec<u8> = Vec::new();
                                                copy.extend(encrypted_data.as_bytes());
                                                let encrypted_payload =
                                                    EncryptedDataPayload::new(copy)?;
                                                let decrypted = encrypted_payload.decrypt(
                                                    Some(&session.newskey),
                                                    Some(&session.appskey),
                                                    fhdr.fcnt() as u32,
                                                )?;

                                                print!(
                                                    "\tDevEui[-4..]: {:}",
                                                    &device.credentials.dev_eui[12..],
                                                );

                                                match decrypted.frm_payload().unwrap() {
                                                    FRMPayload::Data(data) => {
                                                        println!(", Data: {:x?}", data);
                                                    }
                                                    FRMPayload::MACCommands(mac) => {
                                                        print!(", Mac: ");
                                                        for mac_cmd in mac.mac_commands() {
                                                            print!("{:?}, ", mac_cmd);
                                                        }
                                                        println!();
                                                    }
                                                    FRMPayload::None => {
                                                        println!();
                                                    }
                                                }

                                                break;
                                            } else {
                                                println!("\tFailed MIC Validation");
                                            }
                                        }
                                    }
                                    if index == devices.len() - 1 {
                                        println!("\tCould not decrypt");
                                    }
                                }
                            }
                            _ => panic!("Makes no sense to have decrypted data here"),
                        }
                    }
                }
            }
        }
    }
}

use std::fs;
use std::path::Path;

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Credentials {
    app_eui: String,
    app_key: String,
    dev_eui: String,
}

fn hex_encode_reversed(arr: &[u8]) -> String {
    let mut copy = Vec::new();
    copy.extend_from_slice(arr);
    copy.reverse();
    hex::encode(copy).to_uppercase()
}

impl Credentials {
    fn from_console_device(device: helium_console::Device) -> Credentials {
        Credentials {
            app_eui: device.app_eui().clone(),
            app_key: device.app_key().clone(),
            dev_eui: device.dev_eui().clone(),
        }
    }
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

fn compare_bth_flipped(b: &[u8], hex_string: &str) -> Result<bool> {
    let hex_binary: Vec<u8> = hex::decode(hex_string)?.into_iter().rev().collect();
    let hex_ref: &[u8] = hex_binary.as_ref();
    Ok(b == hex_ref)
}

fn key_as_string_to_aes128(input: &str) -> Result<keys::AES128> {
    let key_binary: Vec<u8> = hex::decode(input)?;
    let key: [u8; 16] = [
        key_binary[0],
        key_binary[1],
        key_binary[2],
        key_binary[3],
        key_binary[4],
        key_binary[5],
        key_binary[6],
        key_binary[7],
        key_binary[8],
        key_binary[9],
        key_binary[10],
        key_binary[11],
        key_binary[12],
        key_binary[13],
        key_binary[14],
        key_binary[15],
    ];
    Ok(keys::AES128(key))
}
