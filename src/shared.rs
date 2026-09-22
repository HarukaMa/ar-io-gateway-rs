use std::{
    collections::HashMap,
    hash::Hash,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};

use futures_util::{
    FutureExt,
    future::{BoxFuture, WeakShared},
};

pub(crate) type Flights<K, T> = Arc<Mutex<HashMap<K, Flight<T>>>>;

pub(crate) struct Flight<T: Clone> {
    future: WeakShared<BoxFuture<'static, T>>,
    demand: Weak<Demand>,
}

impl<T: Clone> std::fmt::Debug for Flight<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Flight")
    }
}

pub(crate) fn has_parent() -> bool {
    DEMAND.try_with(|_| ()).is_ok()
}

pub(crate) fn inherit<F: Future>(future: F) -> impl Future<Output = F::Output> {
    let demand = DEMAND.try_with(Arc::clone).ok();
    async move {
        match demand {
            Some(demand) => DEMAND.scope(demand, future).await,
            None => future.await,
        }
    }
}

#[derive(Default)]
struct Demand {
    foreground: AtomicUsize,
    parents: Mutex<Vec<Weak<Demand>>>,
}

impl Demand {
    fn active(&self) -> bool {
        self.foreground.load(Ordering::Relaxed) != 0
            || self
                .parents
                .lock()
                .unwrap()
                .iter()
                .filter_map(Weak::upgrade)
                .any(|parent| parent.active())
    }
}

tokio::task_local! {
    static DEMAND: Arc<Demand>;
}

pub(crate) fn cache_requested() -> bool {
    DEMAND
        .try_with(|demand| demand.active())
        .unwrap_or_else(|_| crate::BACKGROUND_CPU.try_with(|()| ()).is_err())
}

struct Interest {
    demand: Arc<Demand>,
    foreground: bool,
}

impl Drop for Interest {
    fn drop(&mut self) {
        if self.foreground {
            self.demand.foreground.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

// Only callers own strong futures. Dropping the last waiter cancels the work.
pub(crate) fn run<'a, K, T, F>(flights: &'a Flights<K, T>, key: K, future: F) -> BoxFuture<'a, T>
where
    K: Eq + Hash + Send + 'a,
    T: Clone + Send + Sync + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let future = future.boxed();
    Box::pin(async move {
        let background = crate::BACKGROUND_CPU.try_with(|()| ()).is_ok();
        let parent = DEMAND.try_with(Arc::clone).ok();
        let (work, demand) = {
            let mut flights = flights.lock().unwrap();
            let existing = flights
                .get(&key)
                .and_then(|entry| Some((entry.future.upgrade()?, entry.demand.upgrade()?)));
            match existing {
                Some(entry) => entry,
                None => {
                    flights.retain(|_, entry| entry.future.upgrade().is_some());
                    let demand = Arc::new(Demand::default());
                    let work_demand = Arc::clone(&demand);
                    let work = async move {
                        DEMAND
                            .scope(work_demand, async move {
                                if background {
                                    crate::BACKGROUND_CPU.scope((), future).await
                                } else {
                                    future.await
                                }
                            })
                            .await
                    }
                    .boxed()
                    .shared();
                    flights.insert(
                        key,
                        Flight {
                            future: work.downgrade().expect("new shared future"),
                            demand: Arc::downgrade(&demand),
                        },
                    );
                    (work, demand)
                }
            }
        };
        let foreground = parent.is_none() && !background;
        if let Some(parent) = parent {
            let mut parents = demand.parents.lock().unwrap();
            parents.retain(|entry| entry.strong_count() != 0);
            if !parents
                .iter()
                .any(|entry| entry.ptr_eq(&Arc::downgrade(&parent)))
            {
                parents.push(Arc::downgrade(&parent));
            }
        }
        if foreground {
            demand.foreground.fetch_add(1, Ordering::Relaxed);
        }
        let _interest = Interest { demand, foreground };
        work.await
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pending<F: Future>(future: std::pin::Pin<&mut F>) {
        let mut future = future;
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn remaining_waiter_finishes_and_last_waiter_cancels() {
        let flights: Flights<u8, u8> = Default::default();
        let (send, receive) = tokio::sync::oneshot::channel();
        let mut first = Box::pin(run(&flights, 1, async move { receive.await.unwrap() }));
        pending(first.as_mut()).await;
        let mut second = Box::pin(run(&flights, 1, async { panic!("duplicate fetch") }));
        pending(second.as_mut()).await;
        drop(first);
        send.send(7).unwrap();
        assert_eq!(second.await, 7);

        struct Cancelled(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Cancelled {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&cancelled);
        let mut first = Box::pin(run(&flights, 2, async move {
            let _cancelled = Cancelled(observed);
            std::future::pending::<u8>().await
        }));
        pending(first.as_mut()).await;
        let mut second = Box::pin(run(&flights, 2, async { panic!("duplicate fetch") }));
        pending(second.as_mut()).await;
        drop(first);
        assert!(!cancelled.load(Ordering::SeqCst));
        drop(second);
        assert!(cancelled.load(Ordering::SeqCst));
        assert_eq!(run(&flights, 2, async { 9 }).await, 9);
    }

    #[tokio::test]
    async fn foreground_interest_tracks_background_work_without_outliving_caller() {
        for leave in [false, true] {
            let flights: Flights<u8, bool> = Default::default();
            let (send, receive) = tokio::sync::oneshot::channel();
            let mut background = Box::pin(crate::BACKGROUND_CPU.scope(
                (),
                run(&flights, 1, async move {
                    assert!(!cache_requested());
                    receive.await.unwrap();
                    cache_requested()
                }),
            ));
            pending(background.as_mut()).await;
            let mut http = Box::pin(run(&flights, 1, async { panic!("duplicate fetch") }));
            pending(http.as_mut()).await;
            if leave {
                drop(http);
            } else {
                send.send(()).unwrap();
                assert!(http.await);
                assert!(background.await);
                continue;
            }
            send.send(()).unwrap();
            assert!(!background.await);
        }
    }
}
