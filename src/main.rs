use containerd_shim::asynchronous::run;

mod cgroup_memory;
mod common;
mod console;
mod container;
mod io;
mod processes;
mod ironbox_container;
mod service;
mod task;

use service::Service;

#[tokio::main]
async fn main() {
    run::<Service>("io.containerd.ironbox.v1", None).await;
}
