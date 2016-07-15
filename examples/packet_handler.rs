extern crate netfilter_queue as nfq;
extern crate threadpool;

use std::ptr::null;
use nfq::handle::{Handle, ProtocolFamily};
use nfq::queue::{CopyMode, Verdict, PacketHandler, QueueHandle};
use nfq::message::{Message, IPHeader};
use nfq::error::Error;
use threadpool::ThreadPool;
use std::sync::mpsc::channel;
use std::sync::Arc;

fn main() {
    let mut handle = Handle::new().ok().unwrap();
    handle.bind(ProtocolFamily::INET).ok().unwrap();

    let mut queue = handle.queue(1, Decider).ok().unwrap();
    queue.set_mode_sized::<IPHeader>().ok().unwrap();

    println!("Listening for packets...");
    let pool = ThreadPool::new(2);
    let (tx, rx) = channel();
    let arc = Arc::new(handle);
    for _ in 0..2 {
      let tx = tx.clone();
      let arc = arc.clone();
      pool.execute(move || {
        arc.start(4096).unwrap();
        tx.send(()).unwrap();
      });
    }
    let _: Vec<_> = rx.iter().take(2).collect();
    println!("...finished.");
}

struct Decider;

impl PacketHandler for Decider {
    #[allow(non_snake_case)]
    fn handle(&mut self, hq: QueueHandle, message: Result<&Message, &Error>) -> i32 {
        match message {
            Ok(m) => {
                let h = unsafe { m.ip_header() }.unwrap();
                println!("Packet received: {:?} -> {:?}", h.saddr(), h.daddr());
                let _ = Verdict::set_verdict(hq, m.header.id(), Verdict::Accept, 0, null());
            },
            Err(_) => ()
        }
        0
    }
}
