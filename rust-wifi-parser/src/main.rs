// Corey Hartman //
/* Rust library does not do the heavy lifting so we do a lot of offset hunting
Ive never done this much in depth parsing of a pcap so this was fun and a good learning experience */

use pcap::{Capture, Device};
use pcap_file::pcap::{Packet, PacketHeader, PcapReader};
use reqwest::blocking::{Client, Response};
use reqwest::Error;
use serde::Serialize;
use std::os::raw;
use std::path::Path;
use std::{env, fs::File, process::exit};

struct ManagementFrameInfo {
    management_frame_index: usize,
    beacon_id: u8,
    auth_frame_id: u8,
    association_request_id: u8,
    response_identity_id: u8,
}

static MANAGEMENT_FRAME_CONSTANTS: ManagementFrameInfo = ManagementFrameInfo {
    management_frame_index: 18,
    beacon_id: 0x80,
    auth_frame_id: 0x000b,
    association_request_id: 0x0000,
    response_identity_id: 0x0028,
};

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
            let mut management_frame: Option<Box<dyn ManagementFrame>> = None;

            if raw_packet.packet_data[MANAGEMENT_FRAME_CONSTANTS.management_frame_index]
                == MANAGEMENT_FRAME_CONSTANTS.beacon_id
            {
                management_frame = Some(Box::new(BeaconFrame::new(&raw_packet)));
            } else if raw_packet.packet_data[MANAGEMENT_FRAME_CONSTANTS.management_frame_index]
                == MANAGEMENT_FRAME_CONSTANTS.auth_frame_id
            {
                management_frame = Some(Box::new(AuthenicationFrame::new(&raw_packet)));
            }

            if management_frame.is_some() {
                let unwrapped_management_frame: Box<dyn ManagementFrame>;
                unwrapped_management_frame = management_frame.unwrap();

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
            // check for 0x80 indicating a beacon
            if raw_packet.packet_data[MANAGEMENT_FRAME_CONSTANTS.management_frame_index]
                == MANAGEMENT_FRAME_CONSTANTS.beacon_id
            {
                BeaconFrame::new(raw_packet).display_packet_info();
            } else if raw_packet.packet_data[MANAGEMENT_FRAME_CONSTANTS.management_frame_index]
                == MANAGEMENT_FRAME_CONSTANTS.auth_frame_id
            {
                // to do
            }
        }
    }
}

trait ManagementFrame {
    fn get_json(&self) -> String;
    fn display_packet_info(&self);
}

#[derive(Serialize)]
struct ResponseIdentityFrame {
    #[serde(skip_serializing)]
    raw_packet: Box<RawPacket>,
}

impl ManagementFrame for ResponseIdentityFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("\n");
    }
}

impl ResponseIdentityFrame {
    fn new(raw_packet: RawPacket) -> ResponseIdentityFrame {
        ResponseIdentityFrame {
            raw_packet: Box::<RawPacket>::new(raw_packet),
        }
    }
}

#[derive(Serialize)]
struct AssociationRequestFrame {
    #[serde(skip_serializing)]
    raw_packet: Box<RawPacket>,
}

impl ManagementFrame for AssociationRequestFrame {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("\n");
    }
}

impl AssociationRequestFrame {
    fn new(raw_packet: RawPacket) -> AssociationRequestFrame {
        AssociationRequestFrame {
            raw_packet: Box::<RawPacket>::new(raw_packet),
        }
    }
}

#[derive(Serialize)]
struct AuthenicationFrame<'mf> {
    #[serde(skip_serializing)]
    raw_packet: &'mf RawPacket,
}

impl ManagementFrame for AuthenicationFrame<'_> {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("\n");
    }
}

impl AuthenicationFrame<'_> {
    fn new(raw_packet: &RawPacket) -> AuthenicationFrame {
        AuthenicationFrame { raw_packet }
    }
}

#[derive(Serialize)]
struct BeaconFrame<'mf> {
    #[serde(skip_serializing)]
    raw_packet: &'mf RawPacket,
    essid: String,
    bssid: String,
    beacon_interval: String,
    current_channel: String,
    country_code: String,
    transmit_power: String,
    antenna_signal: String,
    is_private_network: bool,
}

impl ManagementFrame for BeaconFrame<'_> {
    fn get_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    fn display_packet_info(&self) {
        println!("Time Stamp: {}", self.raw_packet.get_timestamp());
        println!("ESSID: {}", self.essid);
        println!("BSSID: {}", self.bssid);
        println!("Beacon Interval TU: {}", self.beacon_interval);
        println!("Current Channel: {}", self.current_channel);
        println!("Current Country Code: {}", self.country_code);
        println!("Transmit Power: {}", self.transmit_power);
        println!("Antenna Signal: -{} dBm", self.antenna_signal);
        println!("Privacy is set: {}", self.is_private_network);
        println!("\n");
    }
}

impl BeaconFrame<'_> {
    fn new(raw_packet: &RawPacket) -> BeaconFrame {
        BeaconFrame {
            raw_packet: &raw_packet,
            essid: BeaconFrame::get_essid(&raw_packet),
            bssid: BeaconFrame::get_bssid(&raw_packet),
            beacon_interval: BeaconFrame::get_beacon_interval(&raw_packet),
            transmit_power: BeaconFrame::get_transmit_power(&raw_packet),
            antenna_signal: BeaconFrame::get_antenna_signal(&raw_packet),
            country_code: BeaconFrame::get_country_code(&raw_packet),
            current_channel: BeaconFrame::get_current_channel(&raw_packet),
            is_private_network: BeaconFrame::is_private_network(&raw_packet),
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

    // we get the byte that indicates atenna signal and get the twos comp
    fn get_antenna_signal(raw_packet: &RawPacket) -> String {
        raw_packet.packet_data[18].wrapping_neg().to_string()
    }

    // we check to see if the privacy bit is set
    fn is_private_network(raw_packet: &RawPacket) -> bool {
        (raw_packet.packet_data[52] & 0x10) == 0x10
    }
}

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
    fn new(packet: Packet) -> RawPacket {
        RawPacket {
            packet_header: packet.header,
            packet_data: packet.data.to_vec(),
        }
    }

    fn load_packet(packet: pcap::Packet) -> RawPacket {
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
