use super::*;

use mio::{
    net::UdpSocket,
    {Events, Poll, PollOpt, Ready, Token},
};
use std::net::SocketAddr;

const MINER: Token = Token(0);
const RADIO: Token = Token(1);

#[derive(Debug, StructOpt)]
pub struct Sniff {
    /// IP address and port of miner or light gateway
    /// (eg: 192.168.1.30:1681)
    #[structopt(short, long)]
    host: Option<String>,

    /// disable timestamp on output
    #[structopt(long)]
    disable_ts: bool,

    /// enable tmst on output
    #[structopt(long)]
    enable_tmst: bool,

    /// enable raw payload output
    #[structopt(long)]
    enable_raw_payload: bool,

    /// Incoming socket
    #[structopt(short, long, default_value = "1600")]
    in_port: u16,

    /// Output all frames
    #[structopt(short, long)]
    debug: bool,

    /// Save trace to file
    #[structopt(short, long)]
    log_trace: Option<std::path::PathBuf>,
}

impl Sniff {
    pub async fn run(&self) -> Result {
        // try to parse the CLI iput
        let mut miner_socket = if let Some(host) = &self.host {
            let miner_server = host.parse()?;
            let socket_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let socket = UdpSocket::bind(&socket_addr)?;
            // "connecting" filters for only frames from the server
            socket.connect(miner_server)?;
            println!("Connected");
            Some(socket)
        } else {
            None
        };

        let mut writer = if let Some(path) = &self.log_trace {
            Some(csv::Writer::from_path(path)?)
        } else {
            None
        };

        let mut devices = {
            let mut ret = Vec::new();
            let creds = load_credentials(DEVICES_PATH)?;
            if let Some(creds) = creds {
                for credentials in creds {
                    ret.push(Device::new(credentials))
                }
            }
            ret
        };

        // we in turn put up our own server for the radio to connect to
        let radio_server = SocketAddr::from(([0, 0, 0, 0], self.in_port));
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
                                if self.debug {
                                    println!("{:?}", msg);
                                }
                                if let Packet::Up(Up::PushData(push_data)) = msg {
                                    if let Some(rxpks) = &push_data.data.rxpk {
                                        for rxpk in rxpks {
                                            match SniffedPacket::new(Pkt::Up(rxpk)) {
                                                Ok(packet) => packets.push(packet),
                                                Err(e) => {
                                                    if !self.disable_ts {
                                                        print!(
                                                            "{}  ",
                                                            Utc::now()
                                                                .format("[%F %H:%M:%S%.3f]\t")
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
                                            if !self.disable_ts {
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
                        if self.debug {
                            println!("{:?}", msg);
                        }
                        buffer = [0; 1024];
                        if let Packet::Up(Up::PushData(push_data)) = msg {
                            if let Some(rxpks) = &push_data.data.rxpk {
                                for rxpk in rxpks {
                                    let packet = SniffedPacket::new(Pkt::Up(rxpk))?;
                                    if let Some(wtr) = &mut writer {
                                        wtr.serialize(&packet)?;
                                    }
                                    packets.push(packet)
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                }

                // process all the packets, including tracking Join/JoinAccept,
                // deriving session keys, and decrypting packets when possible
                for packet in packets {
                    process_packet(
                        &mut devices,
                        packet,
                        self.disable_ts,
                        self.enable_tmst,
                        self.enable_raw_payload,
                    )?;
                }

                if let Some(wtr) = &mut writer {
                    wtr.flush()?;
                }
            }
        }
    }
}
