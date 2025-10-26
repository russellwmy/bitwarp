use std::{net::SocketAddr, time::Instant};

use bitwarp_core::error::ErrorKind;
use bitwarp_peer::{Peer, PeerState};
use bitwarp_protocol::packet::{DeliveryGuarantee, OrderingGuarantee, Packet};
use tracing::error;

use crate::{
    event_types::{Action, SocketEvent},
    session::{Session, SessionEventAddress},
};

/// Required by `SessionManager` to properly handle session event.
impl SessionEventAddress for SocketEvent {
    /// Returns event address.
    fn address(&self) -> SocketAddr {
        match self {
            SocketEvent::Packet(packet) => packet.addr(),
            SocketEvent::Connect(addr) => *addr,
            SocketEvent::Timeout(addr) => *addr,
            SocketEvent::Disconnect(addr) => *addr,
        }
    }
}

/// Required by `SessionManager` to properly handle user event.
impl SessionEventAddress for Packet {
    /// Returns event address.
    fn address(&self) -> SocketAddr {
        self.addr()
    }
}

impl Session for Peer {
    type SendEvent = Packet;
    type ReceiveEvent = SocketEvent;

    fn create_session(
        config: &bitwarp_core::config::Config,
        address: SocketAddr,
        time: Instant,
    ) -> Peer {
        Peer::new(address, config, time)
    }

    fn is_established(&self) -> bool {
        self.is_established()
    }

    fn should_drop(&mut self, time: Instant) -> (bool, Vec<Action<Self::ReceiveEvent>>) {
        let mut actions = Vec::new();

        // Check if peer received disconnect command (zombie state)
        if self.state() == PeerState::Zombie {
            actions.push(Action::Emit(SocketEvent::Disconnect(self.remote_address)));
            return (true, actions);
        }

        // Check for timeout or too many packets in flight
        let should_drop = self.packets_in_flight() > self.config().max_packets_in_flight
            || self.last_heard(time) >= self.config().idle_connection_timeout;

        if should_drop {
            actions.push(Action::Emit(SocketEvent::Timeout(self.remote_address)));
            if self.is_established() {
                actions.push(Action::Emit(SocketEvent::Disconnect(self.remote_address)));
            }
        }
        (should_drop, actions)
    }

    fn process_packet(&mut self, payload: &[u8], time: Instant) -> Vec<Action<Self::ReceiveEvent>> {
        let mut actions = Vec::new();
        if !payload.is_empty() {
            // Update inbound bandwidth window and enforce incoming bandwidth limit
            self.update_bandwidth_window(time);
            if !self.can_receive_within_bandwidth() {
                // Over incoming bandwidth limit: drop packet for this window
                tracing::warn!(
                    "Dropping packet ({} bytes) from {} due to incoming bandwidth limit (utilization {:.2})",
                    payload.len(),
                    self.remote_address,
                    self.incoming_bandwidth_utilization()
                );
                return actions; // No actions emitted
            }

            // Track bytes received for bandwidth monitoring (only after passing the limit check)
            self.record_bytes_received(payload.len() as u32);

            // Process command packet
            match self.process_command_packet(payload, time) {
                Ok(packets) => {
                    if self.record_recv() {
                        actions.push(Action::Emit(SocketEvent::Connect(self.remote_address)));
                    }
                    for incoming in packets {
                        actions.push(Action::Emit(SocketEvent::Packet(incoming.0)));
                    }
                }
                Err(err) => error!("Error occurred processing command packet: {:?}", err),
            }
        } else {
            error!("Error processing packet: {}", ErrorKind::ReceivedDataToShort);
        }
        actions
    }

    fn process_event(
        &mut self,
        event: Self::SendEvent,
        _time: Instant,
    ) -> Vec<Action<Self::ReceiveEvent>> {
        let mut actions = Vec::new();
        let addr = self.remote_address;
        if self.record_send() {
            actions.push(Action::Emit(SocketEvent::Connect(addr)));
        }

        // Convert user packet to command
        let channel_id = event.channel_id();
        let ordering = event.order_guarantee();

        match event.delivery_guarantee() {
            DeliveryGuarantee::Reliable => {
                // Use enqueue_reliable_data which handles fragmentation
                // Reliable unordered when ordering is None, otherwise ordered
                let ordered = match ordering {
                    OrderingGuarantee::None => false,
                    _ => true,
                };
                self.enqueue_reliable_data(channel_id, event.payload_arc(), ordered);
            }
            DeliveryGuarantee::Unreliable => {
                use bitwarp_protocol::packet::OrderingGuarantee;

                match ordering {
                    OrderingGuarantee::Unsequenced => {
                        // Unsequenced: prevents duplicates without ordering
                        let unsequenced_group = self.next_unsequenced_group();
                        self.enqueue_command(bitwarp_protocol::command::ProtocolCommand::SendUnsequenced {
                            channel_id,
                            unsequenced_group,
                            data: event.payload_arc().into(),
                        });
                    }
                    _ => {
                        // Regular unreliable (no sequencing or ordering)
                        self.enqueue_command(bitwarp_protocol::command::ProtocolCommand::SendUnreliable {
                            channel_id,
                            data: event.payload_arc().into(),
                        });
                    }
                }
            }
        }

        // Flush commands immediately if within bandwidth
        if self.can_send_within_bandwidth() {
            match self.encode_queued_commands() {
                Ok(bytes) => {
                    // Track bytes for bandwidth throttling
                    self.record_bytes_sent(bytes.len() as u32);
                    actions.push(Action::Send(bytes));
                }
                Err(e) => error!("Error encoding queued commands: {:?}", e),
            }
        }
        // If over bandwidth limit, keep commands queued for next window

        actions
    }

    fn update(&mut self, time: Instant) -> Vec<Action<Self::ReceiveEvent>> {
        let mut actions = Vec::new();

        // Update bandwidth tracking window
        self.update_bandwidth_window(time);

        // Enqueue ping for keepalive if needed
        if self.is_established() {
            if let Some(heartbeat_interval) = self.config().heartbeat_interval {
                // Only send heartbeat when both directions have been idle long enough.
                if self.last_sent(time) >= heartbeat_interval
                    && self.last_heard(time) >= heartbeat_interval
                {
                    // Use command-based Ping for keepalive
                    self.enqueue_ping_command(time.elapsed().as_millis() as u32);
                }
            }
        }

        // Flush any queued commands (ACKs, Pongs, Pings, etc.) if within bandwidth
        if self.has_queued_commands() && self.can_send_within_bandwidth() {
            match self.encode_queued_commands() {
                Ok(bytes) => {
                    // Track bytes for bandwidth throttling
                    self.record_bytes_sent(bytes.len() as u32);
                    actions.push(Action::Send(bytes));
                }
                Err(e) => error!("Error encoding queued commands: {:?}", e),
            }
        }

        // Application-level PMTU discovery & per-peer fragment size tuning
        self.handle_pmtu(time);

        actions
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bitwarp_protocol::{command::ProtocolCommand, command_codec::CommandDecoder};

    use super::*;
    use crate::session::Session;

    fn is_ping(bytes: &[u8]) -> bool {
        // Decompress first (packets are now compressed by default)
        if let Ok(decompressed) = CommandDecoder::decompress(bytes) {
            // Check for command-based Ping only
            if let Ok(packet) = CommandDecoder::decode_packet(&decompressed) {
                return packet
                    .commands
                    .iter()
                    .any(|cmd| matches!(cmd, ProtocolCommand::Ping { .. }));
            }
        }
        false
    }

    #[test]
    fn heartbeat_not_sent_when_recent_inbound() {
        let mut cfg = bitwarp_core::config::Config::default();
        cfg.heartbeat_interval = Some(Duration::from_millis(50));
        let start = Instant::now();

        let mut conn = Peer::new("127.0.0.1:0".parse().unwrap(), &cfg, start);
        // Mark connection as established
        conn.record_send();
        conn.record_recv();

        // Simulate we haven't sent for >= interval but we have received recently
        conn.last_sent = start - Duration::from_millis(55);
        conn.last_heard = start - Duration::from_millis(10);

        let actions = conn.update(start);
        // Expect no ping send
        assert!(actions.iter().all(|a| match a {
            Action::Send(bytes) => !is_ping(bytes),
            _ => true,
        }));
    }

    #[test]
    fn heartbeat_sent_when_bi_idle() {
        let mut cfg = bitwarp_core::config::Config::default();
        cfg.heartbeat_interval = Some(Duration::from_millis(50));
        let start = Instant::now();

        let mut conn = Peer::new("127.0.0.1:0".parse().unwrap(), &cfg, start);
        // Mark connection as established
        conn.record_send();
        conn.record_recv();

        // Both directions idle past interval
        conn.last_sent = start - Duration::from_millis(60);
        conn.last_heard = start - Duration::from_millis(60);

        let actions = conn.update(start);
        // Should send command-based Ping
        assert!(actions.iter().any(|a| match a {
            Action::Send(bytes) => is_ping(bytes),
            _ => false,
        }));
    }

    #[test]
    fn incoming_bandwidth_limit_drops_excess_packets() {
        // Build a small encoded packet from a client peer
        let start = Instant::now();
        let client_cfg = bitwarp_core::config::Config::default();
        let addr = "127.0.0.1:0".parse().unwrap();
        let mut client = Peer::new(addr, &client_cfg, start);

        // Queue a small unreliable packet and encode it
        client.enqueue_unreliable_data(0, vec![1, 2, 3, 4, 5, 6, 7, 8].into());
        let encoded = client.encode_queued_commands().unwrap();

        // Configure server peer with incoming limit equal to one packet size
        let mut server_cfg = bitwarp_core::config::Config::default();
        server_cfg.incoming_bandwidth_limit = encoded.len() as u32; // allow exactly one
        let mut server = Peer::new(addr, &server_cfg, start);

        // First packet should be processed (at least one Packet event emitted)
        let actions1 = <Peer as Session>::process_packet(&mut server, &encoded, start);
        assert!(actions1.iter().any(|a| matches!(a, Action::Emit(SocketEvent::Packet(_)))));

        // Second packet within the same window should be dropped due to limit
        let actions2 = <Peer as Session>::process_packet(&mut server, &encoded, start);
        assert!(actions2.iter().all(|a| !matches!(a, Action::Emit(SocketEvent::Packet(_)))));
    }
}
