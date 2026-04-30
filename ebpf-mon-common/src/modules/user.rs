use core::fmt::Display;

use aya::Pod;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{EventRaw, EventInfo, Type};

unsafe impl Pod for Type {}



#[repr(C)]
#[derive(Debug, Clone)]
pub struct EncodedEvent {
    event: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum DecoderError {
    #[error("not enough bytes to decode")]
    NotEnoughBytes,
    #[error("size of buffer does not match with size of event")]
    SizeDontMatch,
    #[error("Event type is unknown")]
    UnknownType,
}

impl EncodedEvent {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            event: Vec::from(bytes),
        }
    }

    pub fn buffer_len(&self) -> usize {
        self.event.len()
    }

    pub fn from_event<T>(event: EventRaw<T>) -> Self {
        Self::from_bytes(event.encode())
    }

    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    #[inline(always)]
    pub unsafe fn info(&self) -> Result<&EventInfo, DecoderError> {
        // event content must be at least the size of EventInfo
        if self.event.len() < core::mem::size_of::<EventInfo>() {
            return Err(DecoderError::NotEnoughBytes);
        }

        Ok(&(*(self.event.as_ptr() as *const EventInfo)))
    }

    /// Get event info without checking
    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    #[inline(always)]
    pub unsafe fn info_unchecked(&self) -> &EventInfo {
        &(*(self.event.as_ptr() as *const EventInfo))
    }

    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    #[inline(always)]
    pub unsafe fn info_mut(&mut self) -> Result<&mut EventInfo, DecoderError> {
        // event content must be at least the size of EventInfo
        if self.event.len() < core::mem::size_of::<EventInfo>() {
            return Err(DecoderError::NotEnoughBytes);
        }

        Ok(&mut (*(self.event.as_ptr() as *mut EventInfo)))
    }

    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    #[inline(always)]
    pub unsafe fn as_event_with_data<D>(&self) -> Result<&EventRaw<D>, DecoderError> {
        // must be at least the size of Event<T>
        if self.event.len() < core::mem::size_of::<EventRaw<D>>() {
            return Err(DecoderError::SizeDontMatch);
        }

        Ok(&(*(self.event.as_ptr() as *const EventRaw<D>)))
    }

    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    #[inline(always)]
    pub unsafe fn as_mut_event_with_data<D>(&mut self) -> Result<&mut EventRaw<D>, DecoderError> {
        // must be at least the size of Event<T>
        if self.event.len() < core::mem::size_of::<EventRaw<D>>() {
            return Err(DecoderError::SizeDontMatch);
        }

        Ok(&mut (*(self.event.as_mut_ptr() as *mut EventRaw<D>)))
    }
}