//! Integration tests for command encoding and decoding.

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use bitwarp_core::shared::SharedBytes;
    use crate::command::{CommandPacket, ProtocolCommand};
    use super::super::{CommandEncoder, CommandDecoder};

    #[test]
    fn test_encode_decode_send_reliable() {
        let cmd = ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 42,
            ordered: true,
            data: SharedBytes::from_vec(vec![1, 2, 3, 4]),
        };

        let encoded = CommandEncoder::encode_command(&cmd).unwrap();
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = CommandDecoder::decode_command(&mut cursor).unwrap();

        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_acknowledge() {
        let cmd = ProtocolCommand::Acknowledge {
            sequence: 100,
            received_mask: 0xFFFF0000,
            sent_time: Some(12345),
        };

        let encoded = CommandEncoder::encode_command(&cmd).unwrap();
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = CommandDecoder::decode_command(&mut cursor).unwrap();

        assert_eq!(cmd, decoded);
    }

    #[test]
    fn test_encode_decode_packet() {
        let mut packet = CommandPacket::new();
        packet.add_command(ProtocolCommand::Ping { timestamp: 1000 });
        packet.add_command(ProtocolCommand::SendUnreliable { channel_id: 0, data: SharedBytes::from_vec(vec![5, 6, 7]) });
        packet.add_command(ProtocolCommand::Acknowledge {
            sequence: 10,
            received_mask: 0xFF,
            sent_time: None,
        });

        let encoded = CommandEncoder::encode_packet(&packet).unwrap();
        let decoded = CommandDecoder::decode_packet(&encoded).unwrap();

        assert_eq!(packet.commands.len(), decoded.commands.len());
        for (orig, dec) in packet.commands.iter().zip(decoded.commands.iter()) {
            assert_eq!(orig, dec);
        }
    }

    #[test]
    fn test_encode_packet_into_matches_encode_packet() {
        let mut packet = CommandPacket::new();
        packet.add_command(ProtocolCommand::Ping { timestamp: 123 });
        packet.add_command(ProtocolCommand::Pong { timestamp: 456 });
        packet.add_command(ProtocolCommand::Disconnect { reason: 42 });

        let encoded_vec = CommandEncoder::encode_packet(&packet).unwrap();

        let mut into_buf = Vec::new();
        CommandEncoder::encode_packet_into(&mut into_buf, &packet).unwrap();

        assert_eq!(encoded_vec, into_buf);
    }
}
