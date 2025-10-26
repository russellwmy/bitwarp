use std::sync::Arc;

/// A pooled packet buffer that can be reused to reduce allocations.
#[derive(Clone)]
pub struct PooledPacket {
    data: Arc<Vec<u8>>,
    start: usize,
    len: usize,
}

impl PooledPacket {
    /// Creates a new pooled packet from existing data.
    pub fn new(data: Vec<u8>) -> Self {
        let len = data.len();
        Self { data: Arc::new(data), start: 0, len }
    }

    /// Creates a pooled packet as a slice of shared data.
    pub fn from_arc(data: Arc<Vec<u8>>, start: usize, len: usize) -> Self {
        Self { data, start, len }
    }

    /// Returns the packet data as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..self.start + self.len]
    }

    /// Returns the length of the packet.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the packet is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the reference count of the underlying buffer.
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.data)
    }

    /// Converts the pooled packet into owned bytes if this is the only reference.
    /// Otherwise, clones the data.
    pub fn into_owned(self) -> Vec<u8> {
        match Arc::try_unwrap(self.data) {
            Ok(mut vec) => {
                if self.start == 0 && self.len == vec.len() {
                    vec
                } else {
                    vec.drain(self.start..self.start + self.len).collect()
                }
            }
            Err(arc) => arc[self.start..self.start + self.len].to_vec(),
        }
    }
}

impl AsRef<[u8]> for PooledPacket {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::fmt::Debug for PooledPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledPacket")
            .field("len", &self.len)
            .field("ref_count", &self.ref_count())
            .finish()
    }
}

/// A simple packet allocator that reuses buffers.
pub struct PacketAllocator {
    /// Pool of reusable buffers
    pool: Vec<Vec<u8>>,
    /// Size of buffers to allocate
    buffer_size: usize,
    /// Maximum pool size
    max_pool_size: usize,
}

impl PacketAllocator {
    /// Creates a new packet allocator.
    pub fn new(buffer_size: usize, max_pool_size: usize) -> Self {
        Self { pool: Vec::with_capacity(max_pool_size), buffer_size, max_pool_size }
    }

    /// Allocates a buffer from the pool or creates a new one.
    pub fn allocate(&mut self) -> Vec<u8> {
        self.pool.pop().unwrap_or_else(|| Vec::with_capacity(self.buffer_size))
    }

    /// Returns a buffer to the pool for reuse.
    pub fn deallocate(&mut self, mut buffer: Vec<u8>) {
        if self.pool.len() < self.max_pool_size {
            buffer.clear();
            self.pool.push(buffer);
        }
    }

    /// Returns the number of buffers currently in the pool.
    pub fn available(&self) -> usize {
        self.pool.len()
    }

    /// Clears all pooled buffers.
    pub fn clear(&mut self) {
        self.pool.clear();
    }
}

impl Default for PacketAllocator {
    fn default() -> Self {
        Self::new(1500, 256)
    }
}

/// A pool for compression output buffers to reduce allocations in hot paths.
/// Compression can be expensive, so reusing buffers improves performance.
pub struct CompressionBufferPool {
    /// Pool of reusable buffers for compression output
    pool: Vec<Vec<u8>>,
    /// Maximum buffer size to pool (larger buffers are not pooled)
    max_buffer_size: usize,
    /// Maximum number of buffers to keep in pool
    max_pool_size: usize,
}

impl CompressionBufferPool {
    /// Creates a new compression buffer pool.
    pub fn new(max_buffer_size: usize, max_pool_size: usize) -> Self {
        Self {
            pool: Vec::with_capacity(max_pool_size),
            max_buffer_size,
            max_pool_size,
        }
    }

    /// Acquires a buffer from the pool or creates a new one.
    /// The buffer is cleared and ready to use.
    pub fn acquire(&mut self) -> Vec<u8> {
        self.pool.pop().unwrap_or_else(Vec::new)
    }

    /// Returns a buffer to the pool for reuse.
    /// Buffers larger than max_buffer_size are not pooled.
    pub fn release(&mut self, mut buffer: Vec<u8>) {
        if buffer.capacity() <= self.max_buffer_size && self.pool.len() < self.max_pool_size {
            buffer.clear();
            self.pool.push(buffer);
        }
    }

    /// Returns the number of buffers currently available in the pool.
    pub fn available(&self) -> usize {
        self.pool.len()
    }

    /// Clears all pooled buffers.
    pub fn clear(&mut self) {
        self.pool.clear();
    }
}

impl Default for CompressionBufferPool {
    fn default() -> Self {
        // Default: pool buffers up to 8KB, keep up to 32 buffers
        Self::new(8192, 32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pooled_packet_basic() {
        let data = vec![1, 2, 3, 4, 5];
        let packet = PooledPacket::new(data);

        assert_eq!(packet.len(), 5);
        assert_eq!(packet.as_slice(), &[1, 2, 3, 4, 5]);
        assert!(!packet.is_empty());
    }

    #[test]
    fn test_pooled_packet_slice() {
        let data = Arc::new(vec![1, 2, 3, 4, 5]);
        #[allow(clippy::redundant_clone)]
        let packet = PooledPacket::from_arc(data.clone(), 1, 3);

        assert_eq!(packet.len(), 3);
        assert_eq!(packet.as_slice(), &[2, 3, 4]);
    }

    #[test]
    fn test_pooled_packet_ref_count() {
        let data = vec![1, 2, 3];
        let packet1 = PooledPacket::new(data);
        assert_eq!(packet1.ref_count(), 1);

        #[allow(clippy::redundant_clone)]
        let packet2 = packet1.clone();
        assert_eq!(packet1.ref_count(), 2);
        assert_eq!(packet2.ref_count(), 2);
    }

    #[test]
    fn test_allocator_basic() {
        let mut allocator = PacketAllocator::new(100, 10);

        let buf1 = allocator.allocate();
        assert!(buf1.capacity() >= 100);
        assert_eq!(allocator.available(), 0);

        allocator.deallocate(buf1);
        assert_eq!(allocator.available(), 1);

        let buf2 = allocator.allocate();
        assert_eq!(allocator.available(), 0);
        drop(buf2);
    }

    #[test]
    fn test_allocator_max_pool_size() {
        let mut allocator = PacketAllocator::new(100, 2);

        for _ in 0..5 {
            allocator.deallocate(Vec::new());
        }

        assert_eq!(allocator.available(), 2);
    }

    #[test]
    fn test_compression_pool_basic() {
        let mut pool = CompressionBufferPool::new(1024, 10);

        // Acquire a buffer
        let buf1 = pool.acquire();
        assert_eq!(pool.available(), 0);

        // Release it back
        pool.release(buf1);
        assert_eq!(pool.available(), 1);

        // Acquire again - should reuse the buffer
        let buf2 = pool.acquire();
        assert_eq!(pool.available(), 0);
        drop(buf2);
    }

    #[test]
    fn test_compression_pool_size_limit() {
        let mut pool = CompressionBufferPool::new(1024, 5);

        // Create a buffer larger than max_buffer_size
        let mut large_buf = Vec::with_capacity(2048);
        large_buf.extend_from_slice(&[0u8; 2048]);

        pool.release(large_buf);
        // Should not be pooled due to size
        assert_eq!(pool.available(), 0);

        // Create a buffer within size limit
        let mut small_buf = Vec::with_capacity(512);
        small_buf.extend_from_slice(&[0u8; 256]);

        pool.release(small_buf);
        // Should be pooled
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn test_compression_pool_max_pool_size() {
        let mut pool = CompressionBufferPool::new(1024, 3);

        // Try to release more buffers than max_pool_size
        for _ in 0..5 {
            pool.release(Vec::new());
        }

        // Should only keep max_pool_size buffers
        assert_eq!(pool.available(), 3);
    }

    #[test]
    fn test_compression_pool_clear() {
        let mut pool = CompressionBufferPool::default();

        for _ in 0..5 {
            pool.release(Vec::new());
        }

        assert_eq!(pool.available(), 5);

        pool.clear();
        assert_eq!(pool.available(), 0);
    }
}
