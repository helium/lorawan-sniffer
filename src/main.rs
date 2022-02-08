use chrono::Utc;

use serde::{Deserialize, Serialize, Serializer};

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
