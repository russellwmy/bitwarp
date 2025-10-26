/// Peer connection state machine.
///
/// Tracks the lifecycle of a peer connection from initial contact through
/// active communication to graceful shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerState {
    /// Peer has been created but no packets exchanged yet
    #[default]
    Idle,

    /// Client: Sent CONNECT, waiting for VERIFY_CONNECT
    Connecting,

    /// Server: Received CONNECT, sent VERIFY_CONNECT, waiting for ACK
    AcknowledgingConnect,

    /// Client: Received VERIFY_CONNECT, sent ACK, waiting for confirmation
    ConnectionSucceeded,

    /// Both sides have completed handshake - connection is active
    Connected,

    /// Disconnect command sent, waiting for acknowledgment
    Disconnecting,

    /// Peer is being cleaned up (zombie state before removal)
    Zombie,
}

impl PeerState {
    /// Returns true if the peer is in an active state where data can be sent
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            PeerState::Connected
                | PeerState::ConnectionSucceeded
                | PeerState::AcknowledgingConnect
                | PeerState::Connecting
        )
    }

    /// Returns true if the connection is fully established
    pub fn is_established(&self) -> bool {
        matches!(self, PeerState::Connected | PeerState::ConnectionSucceeded)
    }

    /// Returns true if the peer is disconnecting or already disconnected
    pub fn is_disconnecting(&self) -> bool {
        matches!(self, PeerState::Disconnecting | PeerState::Zombie)
    }

    /// Returns true if the peer is in the middle of connection handshake
    pub fn is_connecting(&self) -> bool {
        matches!(
            self,
            PeerState::Connecting | PeerState::AcknowledgingConnect | PeerState::ConnectionSucceeded
        )
    }
}
