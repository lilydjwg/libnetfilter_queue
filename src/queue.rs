//! Queue handling
//!
//! The queue handle and callback,
//! analagous to <http://netfilter.org/projects/libnetfilter_queue/doxygen/group__Queue.html>

use libc::*;
use std::mem;
use std::ptr::null;

use error::*;
use util::*;
use verdict::{PacketHandler, VerdictHandler};
use message::Message;
use lock::NFQ_LOCK as LOCK;

use ffi::*;

enum NFQCopyMode {
    NONE = 0,
    META = 1,
    PACKET = 2
}

/// The amount of data to be copied to userspace for each packet queued.
pub enum CopyMode {
    /// None
    None,
    /// Packet metadata only
    Metadata,
    /// If you copy the packet, you must also specify the size of the packet to copy
    Packet(u16)
}

extern fn queue_callback<A, F: PacketHandler<A>>(qh: *mut nfq_q_handle,
                               nfmsg: *mut nfgenmsg,
                               nfad: *mut nfq_data,
                               cdata: *mut c_void) -> c_int {

    let queue_ptr: *mut Queue<A, F> = unsafe { mem::transmute(cdata) };
    let queue: &mut Queue<A, F> = unsafe { as_mut(&queue_ptr).unwrap() };
    let message = Message::new(nfmsg, nfad);

    queue.callback.handle(qh, &message, &mut queue.data) as c_int
}

/// A handle to an NFQueue queue
///
/// This is used to set queue-specific settings, such as copy-mode and max-length.
pub struct Queue<A, F: PacketHandler<A>> {
    ptr: *mut nfq_q_handle,
    data: A,
    callback: F
}

impl<A, F: PacketHandler<A>> Drop for Queue<A, F> {
    fn drop(&mut self) {
        let ret = unsafe { nfq_destroy_queue(self.ptr) };
        if ret != 0 {
            panic!("Failed to destroy nfq queue");
        }
    }
}

impl<A, F: PacketHandler<A>> Queue<A, F> {
    fn new(handle: *mut nfq_handle,
           queue_number: u16,
           data: A,
           packet_handler: F) -> Result<Box<Queue<A, F>>, Error> {
        let _lock = LOCK.lock().unwrap();

        let nfq_ptr: *const nfq_q_handle = null();
        let mut queue: Box<Queue<A, F>> = Box::new(Queue {
            ptr: nfq_ptr as *mut nfq_q_handle, // set after nfq_create_queue
            data: data,
            callback: packet_handler,
        });
        let queue_ptr: *mut Queue<A, F> = &mut *queue;

        let ptr = unsafe {
            nfq_create_queue(handle,
                             queue_number,
                             queue_callback::<A, F>,
                             mem::transmute(queue_ptr))
        };

        if ptr.is_null() {
            Err(error(Reason::CreateQueue, "Failed to create queue", None))
        } else {
            queue.ptr = ptr;
            Ok(queue)
        }
    }

    /// Set the copy-mode for this queue
    pub fn mode(&mut self, mode: CopyMode) -> Result<(), Error> {
        let copy_mode = match mode {
            CopyMode::None => NFQCopyMode::NONE,
            CopyMode::Metadata => NFQCopyMode::META,
            CopyMode::Packet(_) => NFQCopyMode::PACKET
        } as uint8_t;
        let range = match mode {
            CopyMode::Packet(r) => r,
            _ => 0
        } as uint16_t as uint32_t;

        let res = unsafe { nfq_set_mode(self.ptr, copy_mode, range) };
        if res != 0 {
            Err(error(Reason::SetQueueMode, "Failed to set queue mode", Some(res)))
        } else {
            Ok(())
        }
    }

    /// Set the max-length for this queue
    ///
    /// Once `length` packets are enqueued, packets will be dropped until enqueued packets are processed.
    pub fn maxlen(&mut self, length: u32) -> Result<(), Error> {
        let res = unsafe { nfq_set_queue_maxlen(self.ptr, length) };
        if res != 0 {
            Err(error(Reason::SetQueueMaxlen, "Failed to set queue maxlen", Some(res)))
        } else {
            Ok(())
        }
    }
}

/// A builder for `Queue`
pub struct QueueBuilder<A> {
    ptr: *mut nfq_handle,
    queue_number: uint16_t,
    data: A
}

impl<A> QueueBuilder<A> {
    #[doc(hide)]
    pub fn new(ptr: *mut nfq_handle, data: A) -> QueueBuilder<A> {
        QueueBuilder {
            ptr: ptr,
            queue_number: 0,
            data: data
        }
    }

    /// Set the queue from which the `Queue` will take packets
    pub fn queue_number(self, queue_number: u16) -> QueueBuilder<A> {
        QueueBuilder {
            ptr: self.ptr,
            queue_number: queue_number,
            data: self.data
        }
    }

    /// Create the `Queue` with the provided callback
    pub fn callback_and_finalize<F: PacketHandler<A>>(self, callback: F)
            -> Result<Box<Queue<A, F>>, Error> {
        Queue::new(self.ptr, self.queue_number, self.data, callback)
    }

    /// Create the `Queue` with the provided decider
    ///
    /// A decider is similar to a callback, except that the verdict must be set at the end of the fn.
    /// It is an abstraction suitable for most use cases.
    pub fn decider_and_finalize<F: PacketHandler<A> + VerdictHandler<A>>(self, decider: F)
            -> Result<Box<Queue<A, F>>, Error> {
        Queue::new(self.ptr, self.queue_number, self.data, decider)
    }
}
