use std::collections::VecDeque;

use bitwarp_protocol::command::ProtocolCommand;

/// Command queue for batching protocol commands before transmission.
/// Commands are aggregated into larger packets to improve bandwidth utilization.
#[derive(Debug)]
pub struct CommandQueue {
    /// Pending commands to be processed
    commands: VecDeque<ProtocolCommand>,
    /// Maximum commands to queue before forcing a flush
    max_queue_size: usize,
}

impl CommandQueue {
    /// Creates a new command queue with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        Self { commands: VecDeque::with_capacity(capacity), max_queue_size: capacity }
    }

    /// Enqueues a protocol command for later processing.
    /// Returns true if the queue should be flushed (reached max size).
    pub fn enqueue(&mut self, command: ProtocolCommand) -> bool {
        self.commands.push_back(command);
        self.commands.len() >= self.max_queue_size
    }

    /// Returns the number of queued commands.
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Drains all commands from the queue for processing.
    pub fn drain(&mut self) -> impl Iterator<Item = ProtocolCommand> + '_ {
        self.commands.drain(..)
    }

    /// Returns an iterator over the commands without draining.
    pub fn iter(&self) -> impl Iterator<Item = &ProtocolCommand> {
        self.commands.iter()
    }

    /// Clears all pending commands.
    pub fn clear(&mut self) {
        self.commands.clear();
    }
}

impl Default for CommandQueue {
    fn default() -> Self {
        Self::new(256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_basic_operations() {
        let mut queue = CommandQueue::new(3);

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        queue.enqueue(ProtocolCommand::Ping { timestamp: 100 });
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());
    }

    #[test]
    fn test_queue_max_size_trigger() {
        let mut queue = CommandQueue::new(2);

        assert!(!queue.enqueue(ProtocolCommand::Ping { timestamp: 100 }));
        assert!(queue.enqueue(ProtocolCommand::Ping { timestamp: 200 })); // Should trigger flush

        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_queue_drain() {
        let mut queue = CommandQueue::new(10);

        queue.enqueue(ProtocolCommand::Ping { timestamp: 100 });
        queue.enqueue(ProtocolCommand::Disconnect { reason: 0 });

        let commands: Vec<_> = queue.drain().collect();
        assert_eq!(commands.len(), 2);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_command_aggregation() {
        let mut queue = CommandQueue::new(10);

        // Enqueue multiple protocol commands
        queue.enqueue(ProtocolCommand::SendReliable {
            channel_id: 0,
            sequence: 1,
            ordered: true,
            data: vec![1, 2, 3].into(),
        });
        queue.enqueue(ProtocolCommand::Acknowledge {
            sequence: 5,
            received_mask: 0xFF,
            sent_time: Some(1000),
        });
        queue.enqueue(ProtocolCommand::Ping { timestamp: 2000 });

        assert_eq!(queue.len(), 3);

        // Drain and verify all commands
        let commands: Vec<_> = queue.drain().collect();
        assert_eq!(commands.len(), 3);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_iter() {
        let mut queue = CommandQueue::new(10);

        queue.enqueue(ProtocolCommand::Ping { timestamp: 100 });
        queue.enqueue(ProtocolCommand::Pong { timestamp: 200 });

        let count = queue.iter().count();
        assert_eq!(count, 2);
        assert_eq!(queue.len(), 2); // Iterator shouldn't drain
    }
}
