// Corey Hartman //
/* Rust library does not do the heavy lifting so we do a lot of offset hunting
Ive never done this much in depth parsing of a pcap so this was fun and a good learning experience */
mod Packets;
use pcap::{Capture, Device};
use pcap_file::pcap::PcapReader;
use reqwest::blocking::{Client, Response};
use reqwest::Error;
use std::path::Path;
use std::{env, fs::File, process::exit};
use Packets::management_packets::{
    AssociationRequestFrame, AssociationResponseFrame, AuthenticationFrame, BeaconProbeFrame,
    DeauthenticationFrame, DisassociationFrame, ReassociationFrame,
};
use Packets::packet_bundle::Packets as PacketBundle;

use crate::Packets::management_packets::ManagementFrame;
use crate::Packets::raw_packet::RawPacket;

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

        // iterate over all packets captured
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
        let mut packets: PacketBundle = PacketBundle::new();
        packets.generate_packets_data(pcap_reader);
        packets.display_packets_info();
    } else {
        println!("Incorrect arguments provided!");
    }
}

// determine frame type by checking the 18th element in the array which indicates the subtype of the management frame
// and return that frame struct (using polymorphism 'traits')
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

// converts the management frame into a json and sends it to the provided url.
// if an error occurs we print it to stdout.
fn send_management_frame_to_log(management_frame: Box<dyn ManagementFrame>, greylog_url: &str) {
    let json: String = management_frame.get_json();
    let client: Client = reqwest::blocking::Client::new();
    let result: Result<Response, Error> = client
        .post(greylog_url)
        .body(json)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send();

    // for graylog we want a status code 202 per documentation
    match result {
        Ok(r) => {
            if r.status().as_u16() != 202 {
                println!("GRAYLOG ERROR [STATUS CODE: {}]", r.status())
            }
        }
        Err(e) => println!("ERROR: [{}]", e),
    }
}
