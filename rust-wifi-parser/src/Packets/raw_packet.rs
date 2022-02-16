use pcap_file::pcap::{Packet, PacketHeader};

#[derive(Clone)]
pub struct RawPacket {
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
    pub fn new(packet: Packet) -> Self {
        RawPacket {
            packet_header: packet.header,
            packet_data: packet.data.to_vec(),
        }
    }

    pub fn load_packet(packet: pcap::Packet) -> Self {
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
