use base64;
use helium_console;
use lorawan;
use lorawan::{
    keys,
    parser::{derive_appskey, derive_newskey, GenericPhyPayload, MacPayload},
};
use mio::{
    net::UdpSocket,
    {Events, Poll, PollOpt, Ready, Token},
};
use semtech_udp;
use serde_derive::{Deserialize, Serialize};
use std::{process, time::Duration};
use structopt::StructOpt;

const MINER: Token = Token(0);
const RADIO: Token = Token(1);

const DEVICES_PATH: &str = "lorawan-devices.json";

#[derive(Debug, StructOpt)]
#[structopt(name = "lorawan-sniffer", about = "lorawan sniffing utility")]
struct Opt {
    /// IP address and port of miner mirror port
    /// (eg: 192.168.1.30:1681)
    #[structopt(short, long)]
    miner: String,
    /// Optional API Key to populate devices from console
    #[structopt(short, long)]
    key: Option<String>,
}

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(PartialEq)]
struct DevAddr([u8; 4]);

impl DevAddr {
    fn copy_from_parser(src: &lorawan::parser::DevAddr) -> DevAddr {
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
    last_join_request: Option<GenericPhyPayload<Vec<u8>>>,
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

async fn run(opt: Opt) -> Result {
    // try to parse the CLI iput
    let miner_server = opt.miner.parse()?;
    let mut miner_socket = UdpSocket::bind(&"0.0.0.0:1681".parse()?)?;
    // "connecting" filters for only frames from the server
    miner_socket.connect(miner_server)?;
    // send something so that server can know about us
    miner_socket.send(&[0])?;

    let mut devices = {
        let mut ret = Vec::new();

        if let Some(key) = opt.key {
            let config = helium_console::client::Config::new(key);
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
    let radio_server = "0.0.0.0:1680".parse()?;
    let mut radio_socket = UdpSocket::bind(&radio_server)?;

    // setup the epoll events
    let poll = Poll::new()?;
    poll.register(
        &mut miner_socket,
        MINER,
        Ready::readable(),
        PollOpt::level(),
    )?;
    poll.register(
        &mut radio_socket,
        RADIO,
        Ready::readable(),
        PollOpt::level(),
    )?;

    let mut buffer = [0; 1024];
    let mut events = Events::with_capacity(128);
    // we will stash the client address here when we see it
    // warning: this approach only supports a single radio client
    let mut radio_client = None;

    loop {
        poll.poll(&mut events, Some(Duration::from_millis(100)))?;
        for event in events.iter() {
            let mut packets = Vec::new();
            match event.token() {
                MINER => {
                    let num_recv = miner_socket.recv(&mut buffer)?;
                    // forward the packet along
                    if let Some(radio_client) = &radio_client {
                        radio_socket.send_to(&buffer[0..num_recv], &radio_client)?;
                    }
                    let msg = semtech_udp::Packet::parse(&mut buffer, num_recv)?;
                    buffer = [0; 1024];

                    match msg.data() {
                        semtech_udp::PacketData::PullResp(data) => {
                            let bytes = base64::decode(data.txpk.data.clone()).unwrap();
                            packets.push(GenericPhyPayload::new(bytes)?);
                        }
                        semtech_udp::PacketData::PushData(data) => {
                            if let Some(rxpks) = &data.rxpk {
                                for rxpk in rxpks {
                                    let bytes = base64::decode(rxpk.data.clone()).unwrap();
                                    packets.push(GenericPhyPayload::new(bytes)?)
                                }
                            }
                        }
                        _ => (),
                    }
                }
                RADIO => {
                    let (num_recv, src) = radio_socket.recv_from(&mut buffer)?;
                    radio_client = Some(src);
                    miner_socket.send(&buffer[0..num_recv])?;
                    let msg = semtech_udp::Packet::parse(&mut buffer, num_recv)?;
                    buffer = [0; 1024];
                    if let semtech_udp::PacketData::PushData(data) = msg.data() {
                        if let Some(rxpks) = &data.rxpk {
                            for rxpk in rxpks {
                                let bytes = base64::decode(rxpk.data.clone()).unwrap();
                                packets.push(GenericPhyPayload::new(bytes)?)
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }

            for packet in packets {
                print!("{:?}\t", packet.mhdr().mtype());
                match &packet.mac_payload() {
                    MacPayload::JoinRequest(join_request) => {
                        println!(
                            "AppEui: {:x?} DevEui: {:x?} DevNonce: {:x?}",
                            join_request.app_eui().as_ref(),
                            join_request.dev_eui().as_ref(),
                            join_request.dev_nonce().as_ref()
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
                                device.last_join_request =
                                    Some(GenericPhyPayload::new(packet.inner_ref().clone())?);
                            }
                        }
                    }
                    MacPayload::JoinAccept(_) => {
                        for device in &mut devices {
                            let app_key = key_as_string_to_aes128(&device.credentials.app_key)?;
                            let decrypted_join_accept =
                                GenericPhyPayload::<[u8; 17]>::new_decrypted_join_accept(
                                    packet.inner_ref().clone(),
                                    &app_key,
                                )
                                .unwrap();

                            // If the MIC works, then we have matched a previous join request
                            // join response and we can now derive and save session keys
                            if decrypted_join_accept.validate_join_mic(&app_key).unwrap() {
                                if let MacPayload::JoinAccept(join_accept) =
                                    decrypted_join_accept.mac_payload()
                                {
                                    println!(
                                        "AppNonce: {:x?} NetId: {:x?} DevAddr: {:x?}",
                                        join_accept.app_nonce().as_ref(),
                                        join_accept.net_id().as_ref(),
                                        join_accept.dev_addr().as_ref(),
                                    );
                                    println!(
                                        "\t\tDL Settings: {:x?} RxDelay: {:x?}",
                                        join_accept.dl_settings(),
                                        join_accept.rx_delay()
                                    );

                                    if let Some(phy_join_request) = &device.last_join_request {
                                        if let MacPayload::JoinRequest(join_request) =
                                            phy_join_request.mac_payload()
                                        {
                                            let newskey = derive_newskey(
                                                &join_accept.app_nonce(),
                                                &join_accept.net_id(),
                                                &join_request.dev_nonce(),
                                                &app_key,
                                            );

                                            let appskey = derive_appskey(
                                                &join_accept.app_nonce(),
                                                &join_accept.net_id(),
                                                &join_request.dev_nonce(),
                                                &app_key,
                                            );

                                            println!("\t\tNewskey: {:x?}", newskey);
                                            println!("\t\tAppskey: {:x?}", appskey);

                                            device.session = Some(Session {
                                                newskey,
                                                appskey,
                                                devaddr: DevAddr::copy_from_parser(
                                                    &join_accept.dev_addr(),
                                                ),
                                            });
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    MacPayload::Data(data) => {
                        // print header
                        let fhdr = data.fhdr();
                        print!(
                            "{:x?}, {:x?}, FCnt({:x?})",
                            fhdr.dev_addr(),
                            fhdr.fctrl(),
                            fhdr.fcnt(),
                        );

                        // if there is some FPort => encrypted payload
                        // iterate through our devices until we find a match
                        if let Some(fport) = data.f_port() {
                            println!(", FPort({:?}), ", fport);
                            let devaddr = DevAddr::copy_from_parser(&fhdr.dev_addr());
                            for (index, device) in devices.iter().enumerate() {
                                // if there is a live session, check for address match
                                if let Some(session) = &device.session {
                                    if session.devaddr == devaddr {
                                        let payload = packet.decrypted_payload(
                                            // depending on FPort,
                                            // we use newskey os appskey
                                            if fport == 0 {
                                                &session.newskey
                                            } else {
                                                &session.appskey
                                            },
                                            fhdr.fcnt() as u32,
                                        )?;
                                        println!("\t\t\tDecryptedData({:x?})", payload);
                                        break;
                                    }
                                }
                                // if we are on the last item, print the enrypted data
                                if index == devices.len() - 1 {
                                    println!(
                                        "\t\t\tEncryptedData({:x?})",
                                        data.encrypted_frm_payload().as_ref(),
                                    );
                                }
                            }
                        } else {
                            // insert newline if there is no FPort
                            println!("");
                        }

                        let fopts = fhdr.fopts()?;
                        if fopts.len() > 0 {
                            println!("\t\t\t{:x?}", fopts,);
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

fn compare_bth_flipped(b: &[u8], hex_string: &String) -> Result<bool> {
    let hex_binary: Vec<u8> = hex::decode(hex_string)?.into_iter().rev().collect();
    let hex_ref: &[u8] = hex_binary.as_ref();
    Ok(b == hex_ref)
}

fn key_as_string_to_aes128(input: &String) -> Result<keys::AES128> {
    let app_key = input.clone();
    let key_binary: Vec<u8> = hex::decode(app_key)?;
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
