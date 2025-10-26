use crate::packet::{DeliveryGuarantee, OrderingGuarantee};

/// Represents a communication channel with independent ordering/sequencing.
/// Each peer can have multiple channels for different types of traffic.
#[derive(Debug)]
pub struct Channel {
    /// Channel identifier
    id: u8,
    /// Delivery guarantee for this channel
    delivery: DeliveryGuarantee,
    /// Ordering guarantee for this channel
    ordering: OrderingGuarantee,
}

impl Channel {
    /// Creates a new channel with specified guarantees.
    pub fn new(id: u8, delivery: DeliveryGuarantee, ordering: OrderingGuarantee) -> Self {
        Self { id, delivery, ordering }
    }

    /// Creates an unreliable, unordered channel (like UDP).
    pub fn unreliable(id: u8) -> Self {
        Self::new(id, DeliveryGuarantee::Unreliable, OrderingGuarantee::None)
    }

    /// Creates an unreliable, sequenced channel (drops old packets).
    pub fn unreliable_sequenced(id: u8) -> Self {
        Self::new(id, DeliveryGuarantee::Unreliable, OrderingGuarantee::Sequenced(Some(id)))
    }

    /// Creates a reliable, unordered channel.
    pub fn reliable_unordered(id: u8) -> Self {
        Self::new(id, DeliveryGuarantee::Reliable, OrderingGuarantee::None)
    }

    /// Creates a reliable, ordered channel (like TCP).
    pub fn reliable_ordered(id: u8) -> Self {
        Self::new(id, DeliveryGuarantee::Reliable, OrderingGuarantee::Ordered(Some(id)))
    }

    /// Returns the channel ID.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns the delivery guarantee.
    pub fn delivery(&self) -> DeliveryGuarantee {
        self.delivery
    }

    /// Returns the ordering guarantee.
    pub fn ordering(&self) -> OrderingGuarantee {
        self.ordering
    }
}

/// Manages multiple channels for a connection.
/// Supports up to 255 channels per peer.
#[derive(Debug)]
pub struct ChannelManager {
    /// Array of channels (indexed by channel ID)
    channels: Vec<Channel>,
}

impl ChannelManager {
    /// Creates a new channel manager with the specified number of channels.
    pub fn new(channel_count: u8) -> Self {
        let mut channels = Vec::with_capacity(channel_count as usize);

        // Default: all channels are unreliable unordered
        for id in 0..channel_count {
            channels.push(Channel::unreliable(id));
        }

        Self { channels }
    }

    /// Creates a channel manager with default configuration (1 reliable ordered channel).
    pub fn default_channels() -> Self {
        let mut manager = Self::new(1);
        manager.channels[0] = Channel::reliable_ordered(0);
        manager
    }

    /// Sets the configuration for a specific channel.
    pub fn configure_channel(
        &mut self,
        id: u8,
        delivery: DeliveryGuarantee,
        ordering: OrderingGuarantee,
    ) {
        if let Some(channel) = self.channels.get_mut(id as usize) {
            channel.delivery = delivery;
            channel.ordering = ordering;
        }
    }

    /// Gets a reference to a channel by ID.
    pub fn get_channel(&self, id: u8) -> Option<&Channel> {
        self.channels.get(id as usize)
    }

    /// Returns the total number of channels.
    pub fn channel_count(&self) -> u8 {
        self.channels.len() as u8
    }

    /// Returns an iterator over all channels.
    pub fn channels(&self) -> impl Iterator<Item = &Channel> {
        self.channels.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_creation() {
        let ch = Channel::unreliable(0);
        assert_eq!(ch.id(), 0);
        assert_eq!(ch.delivery(), DeliveryGuarantee::Unreliable);
        assert_eq!(ch.ordering(), OrderingGuarantee::None);

        let ch = Channel::reliable_ordered(1);
        assert_eq!(ch.id(), 1);
        assert_eq!(ch.delivery(), DeliveryGuarantee::Reliable);
        match ch.ordering() {
            OrderingGuarantee::Ordered(_) => (),
            _ => panic!("Expected ordered"),
        }
    }

    #[test]
    fn test_channel_manager() {
        let manager = ChannelManager::new(4);
        assert_eq!(manager.channel_count(), 4);

        let ch0 = manager.get_channel(0).unwrap();
        assert_eq!(ch0.id(), 0);

        let ch3 = manager.get_channel(3).unwrap();
        assert_eq!(ch3.id(), 3);

        assert!(manager.get_channel(4).is_none());
    }

    #[test]
    fn test_channel_presets() {
        let unreliable = Channel::unreliable(0);
        assert_eq!(unreliable.delivery(), DeliveryGuarantee::Unreliable);
        assert_eq!(unreliable.ordering(), OrderingGuarantee::None);

        let sequenced = Channel::unreliable_sequenced(1);
        assert_eq!(sequenced.delivery(), DeliveryGuarantee::Unreliable);
        match sequenced.ordering() {
            OrderingGuarantee::Sequenced(_) => (),
            _ => panic!("Expected sequenced"),
        }

        let reliable = Channel::reliable_unordered(2);
        assert_eq!(reliable.delivery(), DeliveryGuarantee::Reliable);
        assert_eq!(reliable.ordering(), OrderingGuarantee::None);

        let ordered = Channel::reliable_ordered(3);
        assert_eq!(ordered.delivery(), DeliveryGuarantee::Reliable);
        match ordered.ordering() {
            OrderingGuarantee::Ordered(_) => (),
            _ => panic!("Expected ordered"),
        }
    }

    #[test]
    fn test_default_channels() {
        let manager = ChannelManager::default_channels();
        assert_eq!(manager.channel_count(), 1);

        let ch = manager.get_channel(0).unwrap();
        assert_eq!(ch.delivery(), DeliveryGuarantee::Reliable);
        match ch.ordering() {
            OrderingGuarantee::Ordered(_) => (),
            _ => panic!("Expected ordered"),
        }
    }
}
