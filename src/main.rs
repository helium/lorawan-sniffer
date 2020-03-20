#[macro_use]
extern crate serde_derive;
extern crate serde_json;
use semtech_udp;
extern crate arrayref;
use base64;
use lorawan;
use lorawan::keys;
use lorawan::parser::{derive_appskey, derive_newskey, GenericPhyPayload, MacPayload};
use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use std::process;
use std::time::Duration;
use structopt::StructOpt;
use helium_console;

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
            for device in devices {
                ret.push( (Device::from_console_device(device), None) )
            }
        } else {
            let devices = load_devices(DEVICES_PATH)?;
            if let Some(devices) = devices {
                for device in devices {
                    ret.push((device, None));
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
                            packets.push(lorawan::parser::GenericPhyPayload::new(bytes)?);
                        }
                        semtech_udp::PacketData::PushData(data) => {
                            if let Some(rxpks) = &data.rxpk {
                                for rxpk in rxpks {
                                    let bytes = base64::decode(rxpk.data.clone()).unwrap();
                                    packets.push(lorawan::parser::GenericPhyPayload::new(bytes)?)
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
                                packets.push(lorawan::parser::GenericPhyPayload::new(bytes)?)
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
                                &device.0.app_eui,
                            )? && compare_bth_flipped(
                                join_request.dev_eui().as_ref(),
                                &device.0.dev_eui,
                            )? {
                                device.1 =
                                    Some(GenericPhyPayload::new(packet.inner_ref().clone())?);
                            }
                        }
                    }
                    MacPayload::JoinAccept(_) => {
                        for device in &mut devices {
                            let key_binary: Vec<u8> = hex::decode(device.0.app_key.clone())?;
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
                            let app_key = keys::AES128(key);
                            let decrypted_join_accept =
                                GenericPhyPayload::<[u8; 17]>::new_decrypted_join_accept(
                                    packet.inner_ref().clone(),
                                    &app_key,
                                )
                                .unwrap();

                            if decrypted_join_accept.validate_join_mic(&app_key).unwrap() {
                                if let MacPayload::JoinAccept(join_accept) =
                                    decrypted_join_accept.mac_payload()
                                {
                                    print!(
                                        "\r\nAppNonce: {:x?} NetId: {:x?} DevAddr: {:x?}",
                                        join_accept.app_nonce().as_ref(),
                                        join_accept.net_id().as_ref(),
                                        join_accept.dev_addr().as_ref(),
                                    );
                                    println!(
                                        " DL Settings: {:x?} RxDelay: {:x?}",
                                        join_accept.dl_settings(),
                                        join_accept.rx_delay()
                                    );

                                    if let Some(phy_join_request) = &device.1 {
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

                                            println!("newskey: {:x?}", newskey);
                                            println!("appskey: {:x?}", appskey);
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    MacPayload::Data(data) => println!("{:?}", data),
                }
            }
        }
    }
}

use std::fs;
use std::path::Path;

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Device {
    app_eui: String,
    app_key: String,
    dev_eui: String,
}


impl Device {
    fn from_console_device(device: helium_console::Device) -> Device {
        Device {
            app_eui: device.app_eui().clone(),
            app_key: device.app_key().clone(),
            dev_eui: device.dev_eui().clone(),
        }
    }
}

pub fn load_devices(path: &str) -> Result<Option<Vec<Device>>> {
    if !Path::new(path).exists() {
        println!("No lorawan-devices.json found");
        return Ok(None);
    }

    let contents = fs::read_to_string(path)?;
    let devices: Vec<Device> = serde_json::from_str(&contents)?;
    Ok(Some(devices))
}

fn compare_bth_flipped(b: &[u8], hex_string: &String) -> Result<bool> {
    let hex_binary: Vec<u8> = hex::decode(hex_string)?.into_iter().rev().collect();
    let hex_ref: &[u8] = hex_binary.as_ref();
    Ok(b == hex_ref)
}
