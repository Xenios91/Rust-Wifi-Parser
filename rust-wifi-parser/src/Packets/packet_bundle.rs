use std::fs::File;

use pcap_file::{PcapReader, pcap::Packet};

use super::raw_packet::Packet::RawPacket;

// just a struct to store our vector of packets in and to create methods for
pub struct Packets {
    packets: Vec<RawPacket>,
}
impl Packets {
    pub fn new() -> Packets {
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