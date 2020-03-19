use semtech_udp;
extern crate arrayref;
use base64;
use lorawan;
use lorawan::parser::{GenericPhyPayload, MacPayload, derive_newskey, derive_appskey};
use lorawan::keys;
use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use std::error::Error;
use std::time::Duration;

const MINER: Token = Token(0);
const RADIO: Token = Token(1);

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    // hard-code miner address for now
    let miner_server = "192.168.2.68:1680".parse()?;
    let mut miner_socket = UdpSocket::bind(&"0.0.0.0:58058".parse()?)?;
    // "connecting" filters for only frames from the server
    miner_socket.connect(miner_server)?;

    // we in turn hold our own server for the radio to connect to
    let radio_server = "0.0.0.0:1680".parse()?;
    let mut radio_socket = UdpSocket::bind(&radio_server)?;
    // we will figure out the connection later

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

    // we will stash join requests here as we will need them for deriving keys
    let mut last_join_request = None;

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

                    if let semtech_udp::PacketData::PullResp(data) = msg.data() {
                        let bytes = base64::decode(data.txpk.data.clone()).unwrap();
                        packets.push(lorawan::parser::GenericPhyPayload::new(bytes)?);
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

            // debug printing of packet
            for packet in packets {
                print!("{:?}\t", packet.mhdr().mtype());
                match packet.mac_payload() {
                    MacPayload::JoinRequest(join_request) => {
                        println!(
                            "AppEui: {:x?} DevEui: {:x?} DevNonce: {:x?}",
                            join_request.app_eui().as_ref(),
                            join_request.dev_eui().as_ref(),
                            join_request.dev_nonce().as_ref()
                        );
                        last_join_request = Some(packet);
                    }
                    MacPayload::JoinAccept(_) => {
                        let key = [
                            0xEB, 0x31, 0xA2, 0x94, 0x00, 0x51, 0x7C, 0x53, 0x12, 0xCF, 0xBF, 0xD5,
                            0xF5, 0x6F, 0x69, 0xC2,
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

                                if let Some(packet) = &last_join_request {
                                    if let MacPayload::JoinRequest(join_request) =
                                        packet.mac_payload()
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
                            }
                        } else {
                            println!("Invalid MIC!");
                        }
                    }
                    MacPayload::Data(data) => println!("{:?}", data),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use aes::block_cipher_trait::generic_array::GenericArray;
    use aes::block_cipher_trait::BlockCipher;
    use aes::Aes128;
    use openssl::symm::{encrypt, Cipher};
    #[test]
    fn parse_join_response() {
        let input = [
            134, 253, 101, 245, 92, 52, 177, 155, 97, 215, 91, 164, 77, 62, 223, 127,
        ];
        let cipher = Cipher::aes_128_ecb();
        //let key = [0xC2, 0x69, 0x6F, 0xF5, 0xD5, 0xBF, 0xCF, 0x12, 0x53, 0x7C, 0x51, 0x00, 0x94, 0xA2, 0x31, 0xEB];
        let key = [
            0xEB, 0x31, 0xA2, 0x94, 0x00, 0x51, 0x7C, 0x53, 0x12, 0xCF, 0xBF, 0xD5, 0xF5, 0x6F,
            0x69, 0xC2,
        ];
        let iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
                        \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";

        let output = encrypt(cipher, &key, Some(&iv), &input).unwrap();

        println!("output {:x?}", output);
    }

    #[test]
    fn parse_join_response2() {
        let input_bytes = [
            134, 253, 101, 245, 92, 52, 177, 155, 97, 215, 91, 164, 77, 62, 223, 127,
        ];
        let key = [
            0xEB, 0x31, 0xA2, 0x94, 0x00, 0x51, 0x7C, 0x53, 0x12, 0xCF, 0xBF, 0xD5, 0xF5, 0x6F,
            0x69, 0xC2,
        ];
        let key_arr = GenericArray::from_slice(&key);
        let cipher = Aes128::new(key_arr);

        let mut input = GenericArray::clone_from_slice(&input_bytes);
        cipher.encrypt_block(&mut input);
        println!("output {:x?}", input);
    }
}
