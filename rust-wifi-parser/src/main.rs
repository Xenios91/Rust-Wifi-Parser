// Corey Hartman //
/* Rust library does not do the heavy lifting so we do a lot of offset hunting
Ive never done this much in depth parsing of a pcap so this was fun and a good learning experience */
mod packets;
mod monitor_service;
use pcap::{Capture, Device};
use pcap_file::pcap::PcapReader;
use std::path::Path;
use std::{env, fs::File, process::exit};

use packets::packet_bundle::Packets as PacketBundle;
use crate::packets::management_packets::{ManagementFrame};
use crate::packets::raw_packet::RawPacket;
use crate::packets::{management_packets};
use crate::monitor_service::{graylog, monitor_service::send_to_monitor};

fn main() {
    let monitor_url: String = String::from("http://192.168.2.28:9001");

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
                management_packets::build_management_frame(&raw_packet);

            if let Some(unwrapped_management_frame) = management_frame {
                unwrapped_management_frame.display_packet_info();

                if !greylog_url.is_empty() {
                    graylog::send_management_frame_to_log(&unwrapped_management_frame, greylog_url);
                }
                if !monitor_url.is_empty(){
                    send_to_monitor(unwrapped_management_frame, &monitor_url)
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



// just load the pcap and return the reader to the stream
fn load_pcap(file_name: &str) -> PcapReader<File> {
    let file_in: File = File::open(file_name).expect("Error opening file");
    PcapReader::new(file_in).unwrap()
}


