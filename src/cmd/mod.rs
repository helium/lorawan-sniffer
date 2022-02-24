use super::*;
pub mod replay;
pub mod sniff;

#[derive(Debug, StructOpt)]
#[structopt(name = "lorawan-sniffer", about = "lorawan sniffing utility")]
pub enum Cmd {
    Sniff(cmd::sniff::Sniff),
    Replay(cmd::replay::Replay),
}

impl Cmd {
    pub async fn run(&self) -> Result {
        match self {
            Cmd::Sniff(sniff) => sniff.run().await,
            Cmd::Replay(reply) => reply.run().await,
        }
    }
}
