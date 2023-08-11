use std::{
	future::Future,
	net::SocketAddr,
	pin::Pin,
	task::{Context, Poll},
};

use crate::PeerId;

/// can be registered into the P2PManager to extend it's functionality
pub trait Service: Send + Unpin + 'static {
	/// Advertise service to the network.
	/// This will be called when a change to the listen_addr's is made.
	fn advertise(&mut self) {}

	/// Get possible connection candidates for this service.
	/// This is used when the node is trying to connect to a peer.
	fn get_candidates(&mut self, peer_id: PeerId, candidates: &mut Vec<SocketAddr>) {}

	/// Handle an internal event.
	fn on_event(&mut self, event: InternalEvent) {}

	/// TODO: Keep this or not?
	fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()>;
}

/// Wrapper for addressing multiple services at once
#[derive(Default)]
pub(crate) struct Services(Vec<Pin<Box<dyn Service>>>);

impl Services {
	pub fn push(&mut self, service: Pin<Box<dyn Service>>) {
		// 32 comes from `streamunordered` crate which itself comes from `futures` I think.
		// This is to avoid a complicated `Future` implementation and really more than 32 is an edge case we don't care about, rn.
		debug_assert!(
			self.0.len() < 32,
			"Many services will starve the async runtime!"
		);

		self.0.push(service);
	}

	pub fn emit(&mut self, event: InternalEvent) {
		for service in self.0.iter_mut() {
			service.on_event(event.clone());
		}
	}

	pub fn get_candidates(&mut self, peer_id: PeerId, candidates: &mut Vec<SocketAddr>) {
		for service in self.0.iter_mut() {
			service.get_candidates(peer_id, candidates);
		}
	}

	pub fn advertise(&mut self) {
		for service in self.0.iter_mut() {
			service.advertise();
		}
	}
}

impl Future for Services {
	type Output = ();

	fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
		let mut pending = false;

		// TODO: Removing complete futures from poll rotation

		for fut in self.0.iter_mut() {
			match fut.as_mut().poll(cx) {
				Poll::Ready(()) => {}
				Poll::Pending => pending = true,
			}
		}

		// Yield back to runtime to avoid straving other tasks
		// But schedule us to run again cause otherwise we will stall
		if !pending {
			cx.waker().wake_by_ref();
		}

		Poll::Pending
	}
}

// TODO: Maybe merging with `ManagerStreamAction`
/// Internal event for P2PManager to emit to services
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum InternalEvent {
	NewListenAddr(SocketAddr),
	ExpiredListenAddr(SocketAddr),
	Shutdown,
}
