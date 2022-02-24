use super::*;

#[derive(Debug, StructOpt)]
pub struct Replay {
    /// disable timestamp on output
    #[structopt(long)]
    disable_ts: bool,

    /// enable tmst on output
    #[structopt(long)]
    enable_tmst: bool,

    /// enable raw payload output
    #[structopt(long)]
    enable_raw_payload: bool,

    /// Load trace from file
    #[structopt(short, long)]
    log_trace: std::path::PathBuf,
}

impl Replay {
    pub async fn run(&self) -> Result {
        let mut reader = csv::Reader::from_path(&self.log_trace)?;

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

        let mut iter = reader.deserialize();
        while let Some(result) = iter.next() {
            let packet: SniffedPacket = result?;
            process_packet(
                &mut devices,
                packet,
                self.disable_ts,
                self.enable_tmst,
                self.enable_raw_payload,
            )?;
        }

        Ok(())
    }
}
