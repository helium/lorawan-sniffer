use semtech_udp;
extern crate arrayref;
use mio::net::UdpSocket;
use mio::{Events, Poll, PollOpt, Ready, Token};
use std::error::Error;
use std::time::Duration;
use lorawan;
use lorawan::parser::{MacPayload};

use base64;

const MINER: Token = Token(0);
const RADIO: Token = Token(1);

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> Result<()> {
    // hard-code miner address for now
    let miner_server ="192.168.2.68:1680".parse()?;
    let mut miner_socket = UdpSocket::bind(&"0.0.0.0:58058".parse()?)?;
    // "connecting" filters for only frames from the server
    miner_socket.connect(miner_server)?;

    // we in turn hold our own server for the radio to connect to
    let radio_server = "0.0.0.0:1680".parse()?;
    let mut radio_socket = UdpSocket::bind(&radio_server)?;
    // we will figure out the connection alter

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
    // note: this approach only supports a single radio client
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
                        println!("AppEui: {:x?} DevEui: {:x?} DevNonce: {:x?}", 
                            join_request.app_eui().as_ref(), 
                            join_request.dev_eui().as_ref(),  
                            join_request.dev_nonce().as_ref());
                    }
                    MacPayload::JoinAccept(join_accept) => {
                        println!("AppNone: {:x?} NetId: {:x?} DevAddr: {:x?}", 
                            join_accept.app_nonce().as_ref(), 
                            join_accept.net_id().as_ref(),  
                            join_accept.dev_addr().as_ref(),
                        );
                        print!("\tDL Settings: {:x?} RxDelay: {:x?}", 
                            join_accept.dl_settings(),
                            join_accept.rx_delay());
                    }
                    MacPayload::Data(data) => {
                        println!("{:?}", data)
                    }
                }
                

            }
        }
    }
}
