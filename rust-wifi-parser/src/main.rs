// Corey Hartman //
/* Rust library does not do the heavy lifting so we do a lot of offset hunting
Ive never done this much in depth parsing of a pcap so this was fun and a good learning experience */

use pcap::{Capture, Device};
use pcap_file::pcap::{Packet, PacketHeader, PcapReader};
use reqwest::blocking::{Client, Response};
use reqwest::Error;
use serde::Serialize;
use std::path::Path;
use std::{env, fs::File, process::exit};

fn main() {
    // get cli args
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("You must include --pcap [file] or use the --capture [interface] argument to live capture. 
        You can also use --list-devices to get a list of all detected network interfaces.");
        exit(1);
    }

    if args[1].starts_with("--list-devices") {
        let devices = Device::list();
        devices
            .unwrap()
            .iter()
            .for_each(|device: &Device| println!("{}", device.name));
        exit(0);
    }

    if args[1].starts_with("--capture") {
        let devices: Vec<Device> = Device::list().unwrap();
        let mut device: usize = 0;
        let device_name: &str = &args[2];
        let greylog_url: &str;

        if device_name.is_empty() {
            println!("Please supply a device name to capture from!");
            exit(1);
        }

        for (counter, d) in devices.iter().enumerate() {
            if d.name.eq_ignore_ascii_case(device_name) {
                device = counter;
                break;
            }
            if counter == devices.len() - 1 {
                println!("Device [{}] not found!", device_name);
                exit(1);
            }
        }

        if args.len() >= 5 && args[3].contains("--greylog") && !args[4].is_empty() {
            greylog_url = &args[4];
        } else {
            greylog_url = "";
        }

        println!("Starting capture on device: [{}]...", device_name);

        if !greylog_url.is_empty() {
            println!("Capture information will be sent to [{}]...", greylog_url);
        }

        let mut cap = Capture::from_device(devices[device].clone())
            .unwrap()
            .promisc(true)
            .open()
            .unwrap();

        while let Ok(packet) = cap.next() {
            let raw_packet: RawPacket = RawPacket::load_packet(packet);
            let management_frame: Option<Box<dyn ManagementFrame>> =
                build_management_frame(&raw_packet);

            if let Some(unwrapped_management_frame) = management_frame {
                unwrapped_management_frame.display_packet_info();

                if !greylog_url.is_empty() {
                    send_management_frame_to_log(unwrapped_management_frame, greylog_url);
                }
            }
        }
    } else if args.len() == 3 && args[1] == "--pcap" {
        // get cli to get pcap file name
        let file_name: &str = &args[2];
        if !Path::new(file_name).exists() {
            println!("File [{}] not found!", file_name);
            exit(1);
        }

        let pcap_reader: PcapReader<File> = load_pcap(file_name);
        let mut packets: Packets = Packets::new();
        packets.generate_packets_data(pcap_reader);
        packets.display_packets_info();
    } else {
        println!("Incorrect arguments provided!");
    }
}

fn build_management_frame(raw_packet: &RawPacket) -> Option<Box<dyn ManagementFrame>> {
    let mut management_frame: Option<Box<dyn ManagementFrame>> = None;

    // check for hex value indicating management frame type
    if raw_packet.packet_data[18] == 0x80 {
        management_frame = Some(Box::new(BeaconProbeFrame::new(raw_packet)));
    } else if raw_packet.packet_data[18] == 0xb0 {
        management_frame = Some(Box::new(AuthenticationFrame::new(raw_packet)));
    } else if raw_packet.packet_data[18] == 0xc0 {
        management_frame = Some(Box::new(DeauthenticationFrame::new(raw_packet)));
    } else if raw_packet.packet_data[18] == 0x0 {
        management_frame = Some(Box::new(AssociationRequestFrame::new(raw_packet)));
    } else if raw_packet.packet_data[18] == 0x10 {
        management_frame = Some(Box::new(AssociationResponseFrame::new(raw_packet)));
    } else if raw_packet.packet_data[18] == 0xa0 {
        management_frame = Some(Box::new(DisassociationFrame::new(raw_packet)));
    } else if raw_packet.packet_data[18] == 0x20 {
        management_frame = Some(Box::new(ReassociationFrame::new(raw_packet)));
    }
    management_frame
}

// just load the pcap and return the reader to the stream
fn load_pcap(file_name: &str) -> PcapReader<File> {
    let file_in: File = File::open(file_name).expect("Error opening file");
    PcapReader::new(file_in).unwrap()
}

// just a struct to store our vector of packets in and to create methods for
struct Packets {
    packets: Vec<RawPacket>,
}
impl Packets {
    fn new() -> Packets {
        Packets {
            packets: Vec::<RawPacket>::new(),
        }
    }

    // just load all packets from the pcap file into our pcap vector
    fn generate_packets_data(&mut self, pcap_reader: PcapReader<File>) {
        for pcap in pcap_reader {
            let packet: Packet = pcap.unwrap();
            let packet_data: RawPacket = RawPacket::new(packet);
            self.add_packet(packet_data);
        }
    }

    // takes a single packet and adds it to the pcap vector
    fn add_packet(&mut self, packet_data: RawPacket) {
        self.packets.push(packet_data);
    }

    // iterates over all packets in our pcap vector and prints their information
    fn display_packets_info(&self) {
        for raw_packet in self.packets.iter() {
            let management_frame: Option<Box<dyn ManagementFrame>> =
                build_management_frame(raw_packet);

            if let Some(unwrapped_management_frame) = management_frame {
                unwrapped_management_frame.display_packet_info();
                send_management_frame_to_log(unwrapped_management_frame, "");
            }
        }
    }
}

trait ManagementFrame {
    fn get_json(&self) -> String;
    fn display_packet_info(&self);
}

#[derive(Serialize)]
struct AssociationResponseFrame {
    #[serde(skip_serializing)]
    raw_packet: RawPacket,
    short_message: String,
    time_stamp: String,
    antenna_signal: String,
    essid: String,
    bssid: String,
    source_address: String,
    destination_address: String,
}

impl ManagementFrame for AssociationResponseFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("Antenna Signal: -{} dBm", self.antenna_signal);
        println!("ESSID: {}", self.essid);
        println!("BSSID: {}", self.bssid);
        println!("Source Address: {}", self.source_address);
        println!("Destination Address: {}", self.destination_address);
        println!("\n");
    }
}

impl AssociationResponseFrame {
    fn new(raw_packet: &RawPacket) -> Self {
        AssociationResponseFrame {
            raw_packet: raw_packet.to_owned(),
            short_message: String::from("AssociationResponse"),
            time_stamp: raw_packet.get_timestamp(),
            antenna_signal: AssociationResponseFrame::get_antenna_signal(raw_packet),
            essid: String::from("NOT PROVIDED"),
            bssid: AssociationResponseFrame::get_bssid(raw_packet),
            source_address: AssociationResponseFrame::get_source_address(raw_packet),
            destination_address: AssociationResponseFrame::get_destination_address(raw_packet),
        }
    }
    fn get_antenna_signal(raw_packet: &RawPacket) -> String {
        raw_packet.packet_data[14].wrapping_neg().to_string()
    }

    fn get_bssid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 34 to 39 which are the bssid bytes
        let bssid: &[u8] = &raw_packet.packet_data.as_slice()[34..39];
        let mut bssid_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in bssid.iter().enumerate() {
            bssid_vec.push(format!("{:02X}", value));
            if counter != bssid.len() - 1 {
                bssid_vec.push(":".to_string());
            }
        }
        String::from_iter(bssid_vec.into_iter())
    }

    fn get_destination_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[22..27];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_source_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[28..33];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }
}
#[derive(Serialize)]
struct AssociationRequestFrame {
    #[serde(skip_serializing)]
    raw_packet: RawPacket,
    short_message: String,
    time_stamp: String,
    antenna_signal: String,
    essid: String,
    bssid: String,
    source_address: String,
    destination_address: String,
}

impl ManagementFrame for AssociationRequestFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("Antenna Signal: -{} dBm", self.antenna_signal);
        println!("ESSID: {}", self.essid);
        println!("BSSID: {}", self.bssid);
        println!("Source Address: {}", self.source_address);
        println!("Destination Address: {}", self.destination_address);
        println!("\n");
    }
}

impl AssociationRequestFrame {
    fn new(raw_packet: &RawPacket) -> Self {
        AssociationRequestFrame {
            raw_packet: raw_packet.to_owned(),
            short_message: String::from("AssociationRequest"),
            time_stamp: raw_packet.get_timestamp(),
            antenna_signal: AssociationRequestFrame::get_antenna_signal(raw_packet),
            essid: AssociationRequestFrame::get_essid(raw_packet),
            bssid: AssociationRequestFrame::get_bssid(raw_packet),
            source_address: AssociationRequestFrame::get_source_address(raw_packet),
            destination_address: AssociationRequestFrame::get_destination_address(raw_packet),
        }
    }

    fn get_destination_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[22..27];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_source_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[28..33];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_antenna_signal(raw_packet: &RawPacket) -> String {
        raw_packet.packet_data[14].wrapping_neg().to_string()
    }

    fn get_essid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 55 to indicate the essid length
        let essid_length: usize = raw_packet.packet_data[47] as usize;
        // get bytes at offset 56 to the length found and get the bytes between those locations to indicate the essid
        let essid: &[u8] = &raw_packet.packet_data[48..essid_length + 48];
        let essid_string: String = String::from_utf8(essid.to_vec()).unwrap();

        let mut is_hidden: bool = true;
        essid_string.bytes().for_each(|byte: u8| {
            if byte != 0 && is_hidden {
                is_hidden = false;
            }
        });

        if is_hidden {
            return "[HIDDEN SSID]".to_string();
        }

        essid_string
    }

    fn get_bssid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 34 to 39 which are the bssid bytes
        let bssid: &[u8] = &raw_packet.packet_data.as_slice()[34..39];
        let mut bssid_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in bssid.iter().enumerate() {
            bssid_vec.push(format!("{:02X}", value));
            if counter != bssid.len() - 1 {
                bssid_vec.push(":".to_string());
            }
        }
        String::from_iter(bssid_vec.into_iter())
    }
}

#[derive(Serialize)]
struct AuthenticationFrame {
    #[serde(skip_serializing)]
    raw_packet: RawPacket,
    short_message: String,
    time_stamp: String,
    antenna_signal: String,
    essid: String,
    bssid: String,
    source_address: String,
    destination_address: String,
}

impl ManagementFrame for AuthenticationFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("Antenna Signal: -{} dBm", self.antenna_signal);
        println!("ESSID: {}", self.essid);
        println!("BSSID: {}", self.bssid);
        println!("Source Address: {}", self.source_address);
        println!("Destination Address: {}", self.destination_address);
        println!("\n");
    }
}

impl AuthenticationFrame {
    fn new(raw_packet: &RawPacket) -> Self {
        AuthenticationFrame {
            raw_packet: raw_packet.to_owned(),
            short_message: String::from("Authentication"),
            time_stamp: raw_packet.get_timestamp(),
            antenna_signal: AuthenticationFrame::get_antenna_signal(raw_packet),
            essid: String::from("NOT PROVIDED"),
            bssid: AuthenticationFrame::get_bssid(raw_packet),
            source_address: AuthenticationFrame::get_source_address(raw_packet),
            destination_address: AuthenticationFrame::get_destination_address(raw_packet),
        }
    }

    fn get_destination_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[22..27];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_source_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[28..33];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_antenna_signal(raw_packet: &RawPacket) -> String {
        raw_packet.packet_data[14].wrapping_neg().to_string()
    }

    fn get_bssid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 34 to 39 which are the bssid bytes
        let bssid: &[u8] = &raw_packet.packet_data[34..39];
        let mut bssid_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in bssid.iter().enumerate() {
            bssid_vec.push(format!("{:02X}", value));
            if counter != bssid.len() - 1 {
                bssid_vec.push(":".to_string());
            }
        }
        String::from_iter(bssid_vec.into_iter())
    }
}

#[derive(Serialize)]
struct DeauthenticationFrame {
    #[serde(skip_serializing)]
    raw_packet: RawPacket,
    short_message: String,
    time_stamp: String,
    antenna_signal: String,
    essid: String,
    bssid: String,
    source_address: String,
    destination_address: String,
}

impl ManagementFrame for DeauthenticationFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("Antenna Signal: -{} dBm", self.antenna_signal);
        println!("ESSID: {}", self.essid);
        println!("BSSID: {}", self.bssid);
        println!("Source Address: {}", self.source_address);
        println!("Destination Address: {}", self.destination_address);
        println!("\n");
    }
}

impl DeauthenticationFrame {
    fn new(raw_packet: &RawPacket) -> Self {
        DeauthenticationFrame {
            raw_packet: raw_packet.to_owned(),
            short_message: String::from("Deauthentication"),
            time_stamp: raw_packet.get_timestamp(),
            antenna_signal: DeauthenticationFrame::get_antenna_signal(raw_packet),
            essid: String::from("NOT PROVIDED"),
            bssid: DeauthenticationFrame::get_bssid(raw_packet),
            source_address: DeauthenticationFrame::get_source_address(raw_packet),
            destination_address: DeauthenticationFrame::get_destination_address(raw_packet),
        }
    }

    fn get_destination_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[22..27];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_source_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[28..33];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_antenna_signal(raw_packet: &RawPacket) -> String {
        raw_packet.packet_data[14].wrapping_neg().to_string()
    }

    fn get_bssid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 34 to 39 which are the bssid bytes
        let bssid: &[u8] = &raw_packet.packet_data[34..39];
        let mut bssid_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in bssid.iter().enumerate() {
            bssid_vec.push(format!("{:02X}", value));
            if counter != bssid.len() - 1 {
                bssid_vec.push(":".to_string());
            }
        }
        String::from_iter(bssid_vec.into_iter())
    }
}

#[derive(Serialize)]
struct DisassociationFrame {
    #[serde(skip_serializing)]
    raw_packet: RawPacket,
    short_message: String,
    time_stamp: String,
    antenna_signal: String,
    essid: String,
    bssid: String,
    source_address: String,
    destination_address: String,
}

impl ManagementFrame for DisassociationFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("Antenna Signal: -{} dBm", self.antenna_signal);
        println!("ESSID: {}", self.essid);
        println!("BSSID: {}", self.bssid);
        println!("Source Address: {}", self.source_address);
        println!("Destination Address: {}", self.destination_address);
        println!("\n");
    }
}

impl DisassociationFrame {
    fn new(raw_packet: &RawPacket) -> Self {
        DisassociationFrame {
            raw_packet: raw_packet.to_owned(),
            short_message: String::from("Disassociation"),
            time_stamp: raw_packet.get_timestamp(),
            antenna_signal: DisassociationFrame::get_antenna_signal(raw_packet),
            essid: String::from("NOT PROVIDED"),
            bssid: DisassociationFrame::get_bssid(raw_packet),
            source_address: DisassociationFrame::get_source_address(raw_packet),
            destination_address: DisassociationFrame::get_destination_address(raw_packet),
        }
    }

    fn get_destination_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[22..27];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_source_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[28..33];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_antenna_signal(raw_packet: &RawPacket) -> String {
        raw_packet.packet_data[14].wrapping_neg().to_string()
    }

    fn get_bssid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 34 to 39 which are the bssid bytes
        let bssid: &[u8] = &raw_packet.packet_data[34..39];
        let mut bssid_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in bssid.iter().enumerate() {
            bssid_vec.push(format!("{:02X}", value));
            if counter != bssid.len() - 1 {
                bssid_vec.push(":".to_string());
            }
        }
        String::from_iter(bssid_vec.into_iter())
    }
}

#[derive(Serialize)]
struct ReassociationFrame {
    #[serde(skip_serializing)]
    raw_packet: RawPacket,
    short_message: String,
    time_stamp: String,
    antenna_signal: String,
    essid: String,
    bssid: String,
    source_address: String,
    destination_address: String,
}

impl ManagementFrame for ReassociationFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("Antenna Signal: -{} dBm", self.antenna_signal);
        println!("ESSID: {}", self.essid);
        println!("BSSID: {}", self.bssid);
        println!("Source Address: {}", self.source_address);
        println!("Destination Address: {}", self.destination_address);
        println!("\n");
    }
}

impl ReassociationFrame {
    fn new(raw_packet: &RawPacket) -> Self {
        ReassociationFrame {
            raw_packet: raw_packet.to_owned(),
            short_message: String::from("Reassociation"),
            time_stamp: raw_packet.get_timestamp(),
            antenna_signal: ReassociationFrame::get_antenna_signal(raw_packet),
            essid: String::from("NOT PROVIDED"),
            bssid: ReassociationFrame::get_bssid(raw_packet),
            source_address: ReassociationFrame::get_source_address(raw_packet),
            destination_address: ReassociationFrame::get_destination_address(raw_packet),
        }
    }

    fn get_destination_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[22..27];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_source_address(raw_packet: &RawPacket) -> String {
        let address = &raw_packet.packet_data[28..33];
        let mut address_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in address.iter().enumerate() {
            address_vec.push(format!("{:02X}", value));
            if counter != address.len() - 1 {
                address_vec.push(":".to_string());
            }
        }
        String::from_iter(address_vec.into_iter())
    }

    fn get_antenna_signal(raw_packet: &RawPacket) -> String {
        raw_packet.packet_data[14].wrapping_neg().to_string()
    }

    fn get_bssid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 34 to 39 which are the bssid bytes
        let bssid: &[u8] = &raw_packet.packet_data[34..39];
        let mut bssid_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in bssid.iter().enumerate() {
            bssid_vec.push(format!("{:02X}", value));
            if counter != bssid.len() - 1 {
                bssid_vec.push(":".to_string());
            }
        }
        String::from_iter(bssid_vec.into_iter())
    }
}

#[derive(Serialize)]
struct BeaconProbeFrame {
    #[serde(skip_serializing)]
    raw_packet: RawPacket,
    short_message: String,
    time_stamp: String,
    antenna_signal: String,
    essid: String,
    bssid: String,
    beacon_interval: String,
    current_channel: String,
    country_code: String,
    transmit_power: String,
    is_private_network: bool,
}

impl ManagementFrame for BeaconProbeFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("Antenna Signal: -{} dBm", self.antenna_signal);
        println!("ESSID: {}", self.essid);
        println!("BSSID: {}", self.bssid);
        println!("Beacon Interval TU: {}", self.beacon_interval);
        println!("Current Channel: {}", self.current_channel);
        println!("Current Country Code: {}", self.country_code);
        println!("Transmit Power: {}", self.transmit_power);
        println!("Privacy is set: {}", self.is_private_network);
        println!("\n");
    }
}

impl BeaconProbeFrame {
    fn new(raw_packet: &RawPacket) -> Self {
        BeaconProbeFrame {
            raw_packet: raw_packet.to_owned(),
            short_message: String::from("Beacon"),
            time_stamp: raw_packet.get_timestamp(),
            antenna_signal: BeaconProbeFrame::get_antenna_signal(raw_packet),
            essid: BeaconProbeFrame::get_essid(raw_packet),
            bssid: BeaconProbeFrame::get_bssid(raw_packet),
            beacon_interval: BeaconProbeFrame::get_beacon_interval(raw_packet),
            current_channel: BeaconProbeFrame::get_current_channel(raw_packet),
            country_code: BeaconProbeFrame::get_country_code(raw_packet),
            transmit_power: BeaconProbeFrame::get_transmit_power(raw_packet),
            is_private_network: BeaconProbeFrame::is_private_network(raw_packet),
        }
    }
    fn get_essid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 55 to indicate the essid length
        let essid_length: usize = raw_packet.packet_data[55] as usize;
        // get bytes at offset 56 to the length found and get the bytes between those locations to indicate the essid
        let essid: &[u8] = &raw_packet.packet_data[56..essid_length + 56];
        let essid_string: String = String::from_utf8(essid.to_vec()).unwrap();

        let mut is_hidden: bool = true;
        essid_string.bytes().for_each(|byte: u8| {
            if byte != 0 && is_hidden {
                is_hidden = false;
            }
        });

        if is_hidden {
            return "[HIDDEN SSID]".to_string();
        }

        essid_string
    }

    fn get_bssid(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 34 to 39 which are the bssid bytes
        let bssid: &[u8] = &raw_packet.packet_data.as_slice()[34..39];
        let mut bssid_vec: Vec<String> = Vec::<String>::new();
        for (counter, value) in bssid.iter().enumerate() {
            bssid_vec.push(format!("{:02X}", value));
            if counter != bssid.len() - 1 {
                bssid_vec.push(":".to_string());
            }
        }
        String::from_iter(bssid_vec.into_iter())
    }

    fn get_beacon_interval(raw_packet: &RawPacket) -> String {
        // get the bytes at offset 50 to 52 which are the beacon interval bytes indicating how many time units were between intervals
        let beacon_interval: &[u8] = &raw_packet.packet_data.as_slice()[50..52];
        let mut beacon_interval_vec: Vec<String> = vec![beacon_interval[0].to_string()];

        if beacon_interval[1] != 0 {
            beacon_interval_vec.push(beacon_interval[1].to_string());
        }

        String::from_iter(beacon_interval_vec.into_iter())
    }

    // we get the bytes that determine the current channel
    fn get_current_channel(raw_packet: &RawPacket) -> String {
        let offset: usize = raw_packet.get_tag_offset(3) + 2;
        let current_channel: u8 = raw_packet.packet_data[offset];
        current_channel.to_string()
    }

    // we get the bytes that indicate the country code
    fn get_country_code(raw_packet: &RawPacket) -> String {
        let offset: usize = raw_packet.get_tag_offset(7) + 2;
        if offset != 2 {
            let current_country_code: &[u8] = &raw_packet.packet_data[offset..offset + 2];
            return String::from_utf8(current_country_code.to_vec()).unwrap();
        }
        String::from("No Country Code Defined")
    }

    // we get the byte that indicates transmit power
    fn get_transmit_power(raw_packet: &RawPacket) -> String {
        let offset: usize = raw_packet.get_tag_offset(35) + 2;
        if offset != 2 {
            let transmit_power: u8 = raw_packet.packet_data[offset];
            return transmit_power.to_string();
        }
        String::from("No transmit power defined")
    }

    // we check to see if the privacy bit is set
    fn is_private_network(raw_packet: &RawPacket) -> bool {
        (raw_packet.packet_data[52] & 0x10) == 0x10
    }

    fn get_antenna_signal(raw_packet: &RawPacket) -> String {
        raw_packet.packet_data[14].wrapping_neg().to_string()
    }
}

#[derive(Clone)]
struct RawPacket {
    packet_header: PacketHeader,
    packet_data: Vec<u8>,
}

impl RawPacket {
    fn get_timestamp(&self) -> String {
        // built in method to just get the timestamp
        self.packet_header.timestamp().as_millis().to_string()
    }

    // supply a tag id and returns the offset to that tag
    fn get_tag_offset(&self, target_tag: u8) -> usize {
        let tag_start: usize = 54;
        let mut current_offset: usize = tag_start;
        let mut current_tag: u8 = 0;
        let mut tag_found: bool = false;

        while !tag_found {
            if current_tag != target_tag {
                let tag_length: usize = self.packet_data[(current_offset + 1) as usize].into();
                current_offset += tag_length + 2;
                if current_offset >= self.packet_data.len() {
                    current_offset = 0;
                    break;
                }
                current_tag = self.packet_data[(current_offset) as usize];
            } else {
                tag_found = true;
            }
        }
        current_offset
    }

    // just create a new packet based on the byte array supplied
    fn new(packet: Packet) -> Self {
        RawPacket {
            packet_header: packet.header,
            packet_data: packet.data.to_vec(),
        }
    }

    fn load_packet(packet: pcap::Packet) -> Self {
        let packet_header = PacketHeader::new(
            packet.header.ts.tv_sec as u32,
            packet.header.ts.tv_usec as u32,
            packet.header.caplen,
            packet.header.caplen,
        );
        RawPacket {
            packet_header,
            packet_data: packet.data.to_vec(),
        }
    }
}

// converts the management frame into a json and sends it to the provided url.
// if an error occurs we print it to stdout.
fn send_management_frame_to_log(management_frame: Box<dyn ManagementFrame>, greylog_url: &str) {
    let json: String = management_frame.get_json();
    let client: Client = reqwest::blocking::Client::new();
    let result: Result<Response, Error> = client.post(greylog_url).json(&json).send();
    if result.is_err() {
        println!("{}", result.err().unwrap());
    }
}
