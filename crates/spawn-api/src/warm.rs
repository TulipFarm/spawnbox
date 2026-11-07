//! Warm pools: VMs restored ahead of time with their vCPUs paused, so a
//! create only has to resume one.
//!
//! This is the bookkeeping only. The runtime restores, resumes and stops
//! the VMs. `K` tells pools apart besides the build, `V` is a warm VM and
//! `S` is the build it was restored from.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Creates in this window set a pool's target.
pub const DEMAND_WINDOW: Duration = Duration::from_secs(30);
/// Warm VMs being restored at once, over all pools.
const MAX_FILLING: usize = 2;

/// A build that warm VMs are restored from.
pub trait Source {
    /// A replaced or removed build. Its warm VMs are stopped.
    fn is_retired(&self) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Key<K> {
    pub build: String,
    pub kind: K,
}

struct Pool<V, S> {
    template: String,
    source: Weak<S>,
    memory_mib: u64,
    /// Kept at least this many, besides demand.
    min: usize,
    ready: VecDeque<V>,
    filling: usize,
    creates: VecDeque<Instant>,
    hits: u64,
    misses: u64,
}

impl<V, S: Source> Pool<V, S> {
    fn target(&self) -> usize {
        self.min.max(self.creates.len())
    }

    fn live(&self) -> Option<Arc<S>> {
        self.source.upgrade().filter(|s| !s.is_retired())
    }

    fn memory(&self) -> u64 {
        self.memory_mib
            .saturating_mul((self.ready.len() + self.filling) as u64)
    }
}

/// What a pool looks like now.
#[derive(Debug, Serialize)]
pub struct PoolView {
    pub template: String,
    pub build: String,
    pub network: &'static str,
    pub ready: usize,
    pub filling: usize,
    pub target: usize,
    pub hits: u64,
    pub misses: u64,
}

/// A pool that should keep `min` warm VMs.
pub struct Want<K, S> {
    pub key: Key<K>,
    pub template: String,
    pub source: Arc<S>,
    pub memory_mib: u64,
    pub min: usize,
}

/// Work for the runtime after `plan`.
pub struct Plan<K, V, S> {
    /// Restore one warm VM of each, then call `filled`.
    pub fill: Vec<(Key<K>, Arc<S>)>,
    /// Stop these.
    pub stop: Vec<V>,
}

pub struct Warm<K, V, S> {
    budget_mib: u64,
    inner: Mutex<Inner<K, V, S>>,
}

struct Inner<K, V, S> {
    pools: HashMap<Key<K>, Pool<V, S>>,
    closed: bool,
}

impl<K: Clone + Eq + Hash, V, S: Source> Warm<K, V, S> {
    /// `budget_mib` is the memory all warm VMs may have together. 0 turns
    /// warm pools off.
    pub fn new(budget_mib: u64) -> Self {
        Self {
            budget_mib,
            inner: Mutex::new(Inner {
                pools: HashMap::new(),
                closed: false,
            }),
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner<K, V, S>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn enabled(&self) -> bool {
        self.budget_mib > 0
    }

    pub fn budget_mib(&self) -> u64 {
        self.budget_mib
    }

    fn pool<'a>(
        inner: &'a mut Inner<K, V, S>,
        key: &Key<K>,
        template: &str,
        source: &Arc<S>,
        memory_mib: u64,
    ) -> &'a mut Pool<V, S> {
        let pool = inner.pools.entry(key.clone()).or_insert_with(|| Pool {
            template: template.to_owned(),
            source: Arc::downgrade(source),
            memory_mib,
            min: 0,
            ready: VecDeque::new(),
            filling: 0,
            creates: VecDeque::new(),
            hits: 0,
            misses: 0,
        });
        pool.source = Arc::downgrade(source);
        pool
    }

    /// Keeps at least `min` warm VMs of `key`.
    #[cfg(test)]
    pub fn ensure(
        &self,
        key: &Key<K>,
        template: &str,
        source: &Arc<S>,
        memory_mib: u64,
        min: usize,
    ) {
        if !self.enabled() {
            return;
        }
        let mut inner = self.inner();
        Self::pool(&mut inner, key, template, source, memory_mib).min = min;
    }

    /// Sets the minimum of every pool: the ones in `wants`, and 0 for the
    /// rest.
    pub fn set_minimums(&self, wants: &[Want<K, S>]) {
        if !self.enabled() {
            return;
        }
        let mut inner = self.inner();
        for pool in inner.pools.values_mut() {
            pool.min = 0;
        }
        for want in wants {
            Self::pool(
                &mut inner,
                &want.key,
                &want.template,
                &want.source,
                want.memory_mib,
            )
            .min = want.min;
        }
    }

    /// Counts a create and takes a warm VM for it, if one is ready.
    pub fn claim(
        &self,
        key: &Key<K>,
        template: &str,
        source: &Arc<S>,
        memory_mib: u64,
        now: Instant,
    ) -> Option<V> {
        if !self.enabled() {
            return None;
        }
        let mut inner = self.inner();
        let pool = Self::pool(&mut inner, key, template, source, memory_mib);
        pool.creates.push_back(now);
        let vm = pool.ready.pop_front();
        if vm.is_some() {
            pool.hits += 1;
        } else {
            pool.misses += 1;
        }
        vm
    }

    /// Returns a claimed VM that was not used, for example because the
    /// create was over quota. Returns it back if its pool is gone.
    pub fn put_back(&self, key: &Key<K>, vm: V) -> Option<V> {
        let mut inner = self.inner();
        if inner.closed {
            return Some(vm);
        }
        match inner.pools.get_mut(key) {
            Some(pool) if pool.live().is_some() => {
                pool.ready.push_front(vm);
                None
            }
            _ => Some(vm),
        }
    }

    /// Drops old demand and decides what to restore and stop. `free_slots`
    /// is how many slots warm VMs may take now.
    pub fn plan(&self, free_slots: usize, now: Instant) -> Plan<K, V, S> {
        let mut plan = Plan {
            fill: Vec::new(),
            stop: Vec::new(),
        };
        let mut inner = self.inner();
        if inner.closed {
            return plan;
        }
        let cutoff = now.checked_sub(DEMAND_WINDOW);
        inner.pools.retain(|_, pool| {
            if let Some(cutoff) = cutoff {
                while pool.creates.front().is_some_and(|t| *t < cutoff) {
                    pool.creates.pop_front();
                }
            }
            if pool.live().is_none() {
                plan.stop.extend(pool.ready.drain(..));
                return pool.filling > 0;
            }
            let target = pool.target();
            while pool.ready.len() + pool.filling > target && !pool.ready.is_empty() {
                plan.stop.extend(pool.ready.pop_front());
            }
            pool.filling > 0 || !pool.ready.is_empty() || target > 0
        });

        let mut used: u64 = inner.pools.values().map(Pool::memory).sum();
        let mut filling: usize = inner.pools.values().map(|p| p.filling).sum();
        let mut slots = free_slots;
        // Pools with the fewest warm VMs first, then the ones missing most.
        let mut wanting: Vec<(usize, usize, Key<K>)> = inner
            .pools
            .iter()
            .filter_map(|(key, pool)| {
                let have = pool.ready.len() + pool.filling;
                let missing = pool.target().saturating_sub(have);
                (missing > 0).then(|| (have, missing, key.clone()))
            })
            .collect();
        wanting.sort_by_key(|(have, missing, _)| (*have, std::cmp::Reverse(*missing)));
        for (have, missing, key) in wanting {
            let Some(memory_mib) = inner.pools.get(&key).map(|p| p.memory_mib) else {
                continue;
            };
            // An empty pool may take memory from the pool with the most
            // ready VMs, so one busy template cannot starve the others.
            if have == 0 && used.saturating_add(memory_mib) > self.budget_mib {
                let largest = inner
                    .pools
                    .iter_mut()
                    .filter(|(k, p)| **k != key && p.ready.len() > 1)
                    .max_by_key(|(_, p)| p.ready.len())
                    .map(|(_, p)| p);
                if let Some(largest) = largest
                    && let Some(vm) = largest.ready.pop_back()
                {
                    used = used.saturating_sub(largest.memory_mib);
                    plan.stop.push(vm);
                }
            }
            let Some(pool) = inner.pools.get_mut(&key) else {
                continue;
            };
            let Some(source) = pool.live() else {
                continue;
            };
            for _ in 0..missing {
                if filling >= MAX_FILLING
                    || slots == 0
                    || used.saturating_add(pool.memory_mib) > self.budget_mib
                {
                    break;
                }
                pool.filling += 1;
                filling += 1;
                slots -= 1;
                used = used.saturating_add(pool.memory_mib);
                plan.fill.push((key.clone(), Arc::clone(&source)));
            }
        }
        plan
    }

    /// Ends a restore that `plan` asked for. Returns the VM if it should be
    /// stopped instead of kept.
    pub fn filled(&self, key: &Key<K>, vm: Option<V>) -> Option<V> {
        let mut inner = self.inner();
        let closed = inner.closed;
        let pool = inner.pools.get_mut(key)?;
        pool.filling = pool.filling.saturating_sub(1);
        let vm = vm?;
        if closed || pool.live().is_none() {
            return Some(vm);
        }
        pool.ready.push_back(vm);
        None
    }

    /// Takes a warm VM from a pool other than `except`, to free its slot.
    /// Picks the pool with the most ready VMs above its target, then the
    /// one with the most ready VMs.
    pub fn evict(&self, except: Option<&Key<K>>) -> Option<V> {
        let mut inner = self.inner();
        let key = inner
            .pools
            .iter()
            .filter(|(key, pool)| Some(*key) != except && !pool.ready.is_empty())
            .max_by_key(|(_, pool)| {
                let extra = (pool.ready.len() + pool.filling).saturating_sub(pool.target());
                (extra, pool.ready.len())
            })
            .map(|(key, _)| key.clone())?;
        inner.pools.get_mut(&key)?.ready.pop_back()
    }

    /// Stops filling and returns every warm VM.
    pub fn close(&self) -> Vec<V> {
        let mut inner = self.inner();
        inner.closed = true;
        inner
            .pools
            .values_mut()
            .flat_map(|pool| pool.ready.drain(..))
            .collect()
    }

    /// Memory of ready and filling warm VMs, and each pool. `name` names a
    /// pool's `kind`.
    pub fn view(&self, name: impl Fn(&K) -> &'static str) -> (u64, Vec<PoolView>) {
        let inner = self.inner();
        let used = inner.pools.values().map(Pool::memory).sum();
        let mut pools: Vec<PoolView> = inner
            .pools
            .iter()
            .map(|(key, pool)| PoolView {
                template: pool.template.clone(),
                build: key.build.clone(),
                network: name(&key.kind),
                ready: pool.ready.len(),
                filling: pool.filling,
                target: pool.target(),
                hits: pool.hits,
                misses: pool.misses,
            })
            .collect();
        pools.sort_by(|a, b| (&a.template, &a.build).cmp(&(&b.template, &b.build)));
        (used, pools)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[derive(Default)]
    struct Build(AtomicBool);

    impl Source for Build {
        fn is_retired(&self) -> bool {
            self.0.load(Ordering::SeqCst)
        }
    }

    type Pools = Warm<&'static str, u32, Build>;

    fn key(build: &str) -> Key<&'static str> {
        Key {
            build: build.into(),
            kind: "open",
        }
    }

    /// Restores everything the plan asks for, numbering VMs from `next`.
    fn fill(warm: &Pools, slots: usize, now: Instant, next: &mut u32) -> usize {
        let plan = warm.plan(slots, now);
        let count = plan.fill.len();
        for (key, _) in plan.fill {
            *next += 1;
            assert!(warm.filled(&key, Some(*next)).is_none());
        }
        count
    }

    #[test]
    fn min_and_demand_set_the_target() {
        let warm = Pools::new(10_000);
        let build = Arc::new(Build::default());
        let now = Instant::now();
        let mut next = 0;
        warm.ensure(&key("b1"), "base", &build, 1024, 1);
        assert_eq!(fill(&warm, 10, now, &mut next), 1);
        assert_eq!(fill(&warm, 10, now, &mut next), 0);

        assert_eq!(warm.claim(&key("b1"), "base", &build, 1024, now), Some(1));
        assert_eq!(warm.claim(&key("b1"), "base", &build, 1024, now), None);
        assert_eq!(warm.claim(&key("b1"), "base", &build, 1024, now), None);
        // Three creates in the window: three warm VMs, two at a time.
        assert_eq!(fill(&warm, 10, now, &mut next), 2);
        assert_eq!(fill(&warm, 10, now, &mut next), 1);
        let (_, pools) = warm.view(|k| *k);
        assert_eq!((pools[0].ready, pools[0].target), (3, 3));
        assert_eq!((pools[0].hits, pools[0].misses), (1, 2));

        // Demand ends: back to the minimum.
        let later = now + DEMAND_WINDOW + Duration::from_secs(1);
        let plan = warm.plan(10, later);
        assert_eq!(plan.stop, vec![2, 3]);
        assert!(plan.fill.is_empty());
    }

    #[test]
    fn minimums_not_wanted_any_more_fall_to_zero() {
        let warm = Pools::new(10_000);
        let a = Arc::new(Build::default());
        let b = Arc::new(Build::default());
        let now = Instant::now();
        let mut next = 0;
        let want = |k: &str, source: &Arc<Build>| Want {
            key: key(k),
            template: k.into(),
            source: Arc::clone(source),
            memory_mib: 512,
            min: 1,
        };
        warm.set_minimums(&[want("a", &a), want("b", &b)]);
        assert_eq!(fill(&warm, 10, now, &mut next), 2);
        warm.set_minimums(&[want("a", &a)]);
        let plan = warm.plan(10, now);
        assert_eq!(plan.stop.len(), 1);
        let (_, pools) = warm.view(|k| *k);
        assert_eq!(pools.len(), 1);
        assert_eq!((pools[0].template.as_str(), pools[0].target), ("a", 1));
    }

    #[test]
    fn pools_without_demand_fall_to_zero() {
        let warm = Pools::new(10_000);
        let build = Arc::new(Build::default());
        let now = Instant::now();
        let mut next = 0;
        warm.claim(&key("b2"), "py", &build, 512, now);
        assert_eq!(fill(&warm, 10, now, &mut next), 1);
        let plan = warm.plan(10, now + DEMAND_WINDOW * 2);
        assert_eq!(plan.stop, vec![1]);
        assert!(warm.view(|k| *k).1.is_empty());
    }

    #[test]
    fn budget_and_slots_limit_filling() {
        let warm = Pools::new(2048);
        let build = Arc::new(Build::default());
        let now = Instant::now();
        let mut next = 0;
        for _ in 0..5 {
            warm.claim(&key("b1"), "base", &build, 1024, now);
        }
        assert_eq!(fill(&warm, 1, now, &mut next), 1);
        assert_eq!(fill(&warm, 0, now, &mut next), 0);
        assert_eq!(fill(&warm, 10, now, &mut next), 1);
        // 2 GiB budget, 1 GiB each.
        assert_eq!(fill(&warm, 10, now, &mut next), 0);
        assert_eq!(warm.view(|k| *k).0, 2048);
    }

    #[test]
    fn a_busy_pool_does_not_starve_others() {
        let warm = Pools::new(3072);
        let a = Arc::new(Build::default());
        let b = Arc::new(Build::default());
        let now = Instant::now();
        let mut next = 0;
        for _ in 0..10 {
            warm.claim(&key("a"), "a", &a, 1024, now);
        }
        while fill(&warm, 10, now, &mut next) > 0 {}
        warm.claim(&key("b"), "b", &b, 1024, now);
        let plan = warm.plan(10, now);
        assert_eq!(plan.stop, vec![3]);
        assert_eq!(plan.fill.len(), 1);
        assert_eq!(plan.fill[0].0, key("b"));
    }

    #[test]
    fn off_without_budget() {
        let warm = Pools::new(0);
        let build = Arc::new(Build::default());
        warm.ensure(&key("b1"), "base", &build, 1024, 1);
        assert_eq!(
            warm.claim(&key("b1"), "base", &build, 1024, Instant::now()),
            None
        );
        assert!(warm.plan(10, Instant::now()).fill.is_empty());
        assert!(warm.view(|k| *k).1.is_empty());
    }

    #[test]
    fn retired_builds_are_stopped() {
        let warm = Pools::new(10_000);
        let build = Arc::new(Build::default());
        let now = Instant::now();
        let mut next = 0;
        warm.ensure(&key("b1"), "base", &build, 1024, 2);
        let plan = warm.plan(10, now);
        assert_eq!(plan.fill.len(), 2);
        let (first, second) = (plan.fill[0].0.clone(), plan.fill[1].0.clone());
        drop(plan);
        next += 1;
        assert!(warm.filled(&first, Some(next)).is_none());
        build.0.store(true, Ordering::SeqCst);
        // Finished after the build was replaced: stopped right away.
        assert_eq!(warm.filled(&second, Some(9)), Some(9));
        assert_eq!(warm.plan(10, now).stop, vec![1]);
        assert!(warm.view(|k| *k).1.is_empty());
        assert_eq!(warm.put_back(&key("b1"), 5), Some(5));

        // A dropped build too.
        let gone = Arc::new(Build::default());
        warm.ensure(&key("b2"), "base", &gone, 1024, 1);
        assert_eq!(fill(&warm, 10, now, &mut next), 1);
        drop(gone);
        assert_eq!(warm.plan(10, now).stop, vec![next]);
    }

    #[test]
    fn evict_prefers_other_pools_above_target() {
        let warm = Pools::new(10_000);
        let a = Arc::new(Build::default());
        let b = Arc::new(Build::default());
        let now = Instant::now();
        let mut next = 0;
        warm.ensure(&key("a"), "a", &a, 512, 2);
        warm.ensure(&key("b"), "b", &b, 512, 1);
        assert_eq!(fill(&warm, 10, now, &mut next), 2);
        assert_eq!(fill(&warm, 10, now, &mut next), 1);
        assert!(warm.evict(Some(&key("a"))).is_some());
        assert_eq!(warm.evict(Some(&key("a"))), None);
        warm.ensure(&key("a"), "a", &a, 512, 0);
        assert!(warm.evict(None).is_some());
    }

    #[test]
    fn closed_pools_hand_back_everything() {
        let warm = Pools::new(10_000);
        let build = Arc::new(Build::default());
        let now = Instant::now();
        warm.ensure(&key("b1"), "base", &build, 1024, 2);
        let plan = warm.plan(10, now);
        let (first, second) = (plan.fill[0].0.clone(), plan.fill[1].0.clone());
        assert!(warm.filled(&first, Some(1)).is_none());
        assert_eq!(warm.close(), vec![1]);
        assert_eq!(warm.filled(&second, Some(2)), Some(2));
        assert!(warm.plan(10, now).fill.is_empty());
        assert_eq!(warm.put_back(&key("b1"), 3), Some(3));
    }
}
