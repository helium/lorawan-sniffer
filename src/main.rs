use chrono::Utc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use std::time::Duration;
use structopt::StructOpt;

mod cmd;

const DEVICES_PATH: &str = "lorawan-devices.json";

pub type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

mod types;

use types::*;

#[tokio::main]
async fn main() -> Result {
    let cli = cmd::Cmd::from_args();
    while let Err(e) = cli.run().await {
        println!("error: {}", e);
    }
    Ok(())
}

use num_format::Locale::en;
use num_format::{Locale, ToFormattedString};

pub fn process_packet(
    devices: &mut Vec<Device>,
    packet: types::SniffedPacket,
    disable_ts: bool,
    enable_tmst: bool,
    enable_raw_payload: bool,
) -> Result {
    if disable_ts {
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
    if let (Some(lsnr), Some(rssi)) = (&packet.lsnr, &packet.rssi) {
        println!("\tRSSI: {:}\tLSNR: {:}", rssi, lsnr);
    } else {
        println!();
    }

    if enable_tmst {
        println!("\ttmst: {}", packet.tmst.to_formatted_string(&Locale::en));
    }

    match &packet.payload() {
        PhyPayload::JoinRequest(join_request) => {
            if enable_raw_payload {
                println!("\tPhyPayload: {:?} ", join_request.as_bytes())
            }

            println!(
                "\t  AppEui: {:} DevEui: {:} DevNonce: {:}",
                hex_encode_reversed(join_request.app_eui().as_ref()),
                hex_encode_reversed(join_request.dev_eui().as_ref()),
                hex_encode_reversed(join_request.dev_nonce().as_ref())
            );

            for device in &mut *devices {
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
            if enable_raw_payload {
                println!("\tPhyPayload: {:?} ", join_accept.as_bytes())
            }

            for device in &mut *devices {
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
                    if let Some(c_f_list) = decrypted_join_accept.c_f_list() {
                        println!(
                            "\tDL Settings: {:x?} RxDelay: {:x?}, CFList: {:x?}",
                            decrypted_join_accept.dl_settings(),
                            decrypted_join_accept.rx_delay(),
                            c_f_list
                        );
                    } else {
                        println!(
                            "\tDL Settings: {:x?} RxDelay: {:x?}",
                            decrypted_join_accept.dl_settings(),
                            decrypted_join_accept.rx_delay(),
                        );
                    }

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
                            devaddr: DevAddr::copy_from_parser(&decrypted_join_accept.dev_addr()),
                        });
                    }
                    break;
                }
            }
        }
        PhyPayload::Data(data) => {
            if enable_raw_payload {
                println!("\tPhyPayload: {:?} ", data.as_bytes())
            }
            match data {
                DataPayload::Encrypted(encrypted_data) => {
                    let fport = match encrypted_data.f_port() {
                        Some(fport) => format!("FPort {}", fport),
                        None => "No FPort".to_string(),
                    };
                    let confirmed = if encrypted_data.is_confirmed() {
                        "Confirmed"
                    } else {
                        "Unconfirmed"
                    };
                    let fhdr = encrypted_data.fhdr();
                    let ack = fhdr.fctrl().ack();
                    let adr = fhdr.fctrl().adr();
                    let fpending = fhdr.fctrl().f_pending();
                    let foptslen = fhdr.fctrl().f_opts_len();
                    println!(
                        "\tDevAddr: {:}, FCtrl(Ack={ack},Adr={adr},FPending={fpending},FOptsLen={foptslen}), FCnt x{:x?}, {}",
                        hex_encode_reversed(fhdr.dev_addr().as_ref()),
                        fhdr.fcnt(),
                        fport
                    );

                    let devaddr = DevAddr::copy_from_parser(&fhdr.dev_addr());

                    // fopts is a lazy iterator, so we need some boolean logic
                    print_mac(&mut fhdr.fopts(), true);

                    let len = devices.len();
                    for (index, device) in (*devices).iter_mut().enumerate() {
                        // if there is a live session, check for address match
                        if let Some(session) = &device.session {
                            if session.devaddr == devaddr {
                                if encrypted_data.validate_mic(&session.newskey, fhdr.fcnt() as u32)
                                {
                                    let mut copy: Vec<u8> = Vec::new();
                                    copy.extend(encrypted_data.as_bytes());
                                    let encrypted_payload = EncryptedDataPayload::new(copy)?;
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
                                            print_mac(&mut mac.mac_commands(), true);
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
                        if index == len - 1 {
                            println!("\tCould not decrypt");
                        }
                    }
                }
                _ => panic!("Makes no sense to have decrypted data here"),
            }
        }
    }
    Ok(())
}

fn hex_encode_reversed(arr: &[u8]) -> String {
    let mut copy = Vec::new();
    copy.extend_from_slice(arr);
    copy.reverse();
    hex::encode(copy).to_uppercase()
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

fn print_mac(mac_cmd_iterator: &mut MacCommandIterator, with_indent: bool) {
    for mac_cmd in mac_cmd_iterator {
        if with_indent {
            print!("\t")
        }
        if let MacCommand::LinkADRReq(adr_req) = mac_cmd {
            println!(
                "LinkAdrReqPayload(DR({:x?}), TxPower({:x?}), {:x?}, {:x?})",
                adr_req.data_rate(),
                adr_req.tx_power(),
                adr_req.channel_mask(),
                adr_req.redundancy(),
            );
        } else {
            println!("{:x?}", mac_cmd);
        }
    }
}
