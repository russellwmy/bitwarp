use std::sync::Arc;

/// SharedBytes is a reference-counted, sliceable byte buffer.
///
/// It holds an `Arc<[u8]>` plus a (start, len) view, allowing cheap
/// zero-copy slicing that still dereferences to `&[u8]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedBytes {
    data: Arc<[u8]>,
    start: usize,
    len: usize,
}

impl SharedBytes {
    /// Creates a new SharedBytes from a Vec by taking ownership.
    pub fn from_vec(vec: Vec<u8>) -> Self {
        let arc: Arc<[u8]> = Arc::from(vec.into_boxed_slice());
        let len = arc.len();
        Self { data: arc, start: 0, len }
    }

    /// Creates a new SharedBytes from an Arc<[u8]> covering the full slice.
    pub fn from_arc(data: Arc<[u8]>) -> Self {
        let len = data.len();
        Self { data, start: 0, len }
    }

    /// Creates a sub-slice view into the current buffer without copying.
    /// Panics if the requested range is out of bounds.
    pub fn slice(&self, start: usize, len: usize) -> Self {
        assert!(start <= self.len, "slice start out of bounds");
        assert!(start + len <= self.len, "slice end out of bounds");
        Self { data: self.data.clone(), start: self.start + start, len }
    }

    /// Returns the current view as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.start..self.start + self.len]
    }

    /// Returns the length of the current view.
    pub fn len(&self) -> usize { self.len }

    /// Returns true if the view is empty.
    pub fn is_empty(&self) -> bool { self.len == 0 }

    /// Returns the inner Arc if the view covers the whole buffer.
    pub fn into_full_arc(self) -> Option<Arc<[u8]>> {
        if self.start == 0 && self.len == self.data.len() {
            Some(self.data)
        } else {
            None
        }
    }
}

impl From<Vec<u8>> for SharedBytes {
    fn from(v: Vec<u8>) -> Self { Self::from_vec(v) }
}

impl From<Arc<[u8]>> for SharedBytes {
    fn from(a: Arc<[u8]>) -> Self { Self::from_arc(a) }
}

impl AsRef<[u8]> for SharedBytes {
    fn as_ref(&self) -> &[u8] { self.as_slice() }
}
