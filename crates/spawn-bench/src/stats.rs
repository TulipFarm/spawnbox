/// Nearest-rank percentile. `p` is 0..=100.
pub fn percentile(samples: &[f64], p: f64) -> Option<f64> {
    if samples.is_empty() || !(0.0..=100.0).contains(&p) {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.saturating_sub(1)])
}

#[cfg(test)]
mod tests {
    use super::percentile;

    fn one_to(n: u32) -> Vec<f64> {
        (1..=n).rev().map(f64::from).collect()
    }

    #[test]
    fn uses_nearest_rank_on_unsorted_input() {
        assert_eq!(percentile(&one_to(10), 50.0), Some(5.0));
        assert_eq!(percentile(&one_to(20), 95.0), Some(19.0));
        assert_eq!(percentile(&one_to(20), 100.0), Some(20.0));
        assert_eq!(percentile(&one_to(20), 0.0), Some(1.0));
    }

    #[test]
    fn rejects_empty_input_and_bad_rank() {
        assert_eq!(percentile(&[], 50.0), None);
        assert_eq!(percentile(&[1.0], 101.0), None);
    }
}
