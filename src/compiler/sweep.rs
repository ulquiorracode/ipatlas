use crate::compiler::parser::{RawGeoRecord, RawGeoRecordV6, RawPxRecord, RawPxRecordV6};
use crate::models::{FeatureMask, OptimizationConfig};

/// Merged IPv4 interval entry containing unified integer-interned metadata.
/// 100% zero-heap allocation: Copy, 28 bytes, CPU cache-line friendly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergedEntry {
    pub ip_from: u32,
    pub ip_to: u32,
    pub country: [u8; 2],
    pub reg_idx: u16,
    pub city_idx: u32,
    pub isp_idx: u16,
    pub asn: u32,
    pub flags: u16,
    pub lat_fixed: i16,
    pub lon_fixed: i16,
}

impl MergedEntry {
    /// Compares metadata attributes for coalescing adjacent intervals via fast integer registers.
    #[inline(always)]
    pub fn matches_attributes(&self, other: &Self) -> bool {
        self.country == other.country
            && self.city_idx == other.city_idx
            && self.reg_idx == other.reg_idx
            && self.isp_idx == other.isp_idx
            && self.asn == other.asn
            && self.flags == other.flags
            && self.lat_fixed == other.lat_fixed
            && self.lon_fixed == other.lon_fixed
    }
}

/// 1D Sweep-Line Merger with on-the-fly Interval Coalescing (IPv4).
pub struct SweepLineMerger<G, P> {
    geo_iter: G,
    px_iter: P,
    cur_geo: Option<RawGeoRecord>,
    cur_px: Option<RawPxRecord>,
    pending_prev: Option<MergedEntry>,
    features: FeatureMask,
    opt: OptimizationConfig,
    finished: bool,
}

impl<G, P> SweepLineMerger<G, P>
where
    G: Iterator<Item = RawGeoRecord>,
    P: Iterator<Item = RawPxRecord>,
{
    pub fn new(
        mut geo_iter: G,
        mut px_iter: P,
        features: FeatureMask,
        opt: OptimizationConfig,
    ) -> Self {
        let cur_geo = geo_iter.next();
        let cur_px = px_iter.next();
        Self {
            geo_iter,
            px_iter,
            cur_geo,
            cur_px,
            pending_prev: None,
            features,
            opt,
            finished: false,
        }
    }

    #[inline(always)]
    fn make_entry(
        features: FeatureMask,
        opt: &OptimizationConfig,
        ip_from: u32,
        ip_to: u32,
        geo: Option<&RawGeoRecord>,
        px: Option<&RawPxRecord>,
    ) -> MergedEntry {
        let country = if features.has_country() {
            geo.map(|g| g.country).unwrap_or(*b"--")
        } else {
            *b"--"
        };

        let reg_idx = if features.has_region() {
            geo.map(|g| g.reg_idx).unwrap_or(0)
        } else {
            0
        };

        let city_idx = if features.has_city() {
            geo.map(|g| g.city_idx).unwrap_or(0)
        } else {
            0
        };

        let isp_idx = if features.has_isp() {
            px.map(|p| p.isp_idx).unwrap_or(0)
        } else {
            0
        };

        let asn = if features.has_asn() {
            px.map(|p| p.asn).unwrap_or(0)
        } else {
            0
        };

        let mut flags = if features.has_threats() {
            px.map(|p| p.flags).unwrap_or(0)
        } else {
            0
        };

        if opt.collapse_threats && flags != 0 {
            flags = crate::models::GeoFlags::PROXY;
        }

        let (mut lat_fixed, mut lon_fixed) = if features.has_coords() {
            (
                geo.map(|g| g.lat_fixed).unwrap_or(0),
                geo.map(|g| g.lon_fixed).unwrap_or(0),
            )
        } else {
            (0, 0)
        };

        if opt.lossy_coords {
            lat_fixed = crate::models::quantize_coordinate(lat_fixed);
            lon_fixed = crate::models::quantize_coordinate(lon_fixed);
        }

        MergedEntry {
            ip_from,
            ip_to,
            country,
            reg_idx,
            city_idx,
            isp_idx,
            asn,
            flags,
            lat_fixed,
            lon_fixed,
        }
    }

    fn advance_sweep(&mut self) -> Option<MergedEntry> {
        match (self.cur_geo.as_ref(), self.cur_px.as_ref()) {
            (None, None) => None,
            (Some(g), None) => {
                let entry =
                    Self::make_entry(self.features, &self.opt, g.ip_from, g.ip_to, Some(g), None);
                self.cur_geo = self.geo_iter.next();
                Some(entry)
            }
            (None, Some(p)) => {
                let entry =
                    Self::make_entry(self.features, &self.opt, p.ip_from, p.ip_to, None, Some(p));
                self.cur_px = self.px_iter.next();
                Some(entry)
            }
            (Some(g), Some(p)) => {
                if g.ip_to < p.ip_from {
                    let entry = Self::make_entry(
                        self.features,
                        &self.opt,
                        g.ip_from,
                        g.ip_to,
                        Some(g),
                        None,
                    );
                    self.cur_geo = self.geo_iter.next();
                    return Some(entry);
                }
                if p.ip_to < g.ip_from {
                    let entry = Self::make_entry(
                        self.features,
                        &self.opt,
                        p.ip_from,
                        p.ip_to,
                        None,
                        Some(p),
                    );
                    self.cur_px = self.px_iter.next();
                    return Some(entry);
                }

                let start = g.ip_from.min(p.ip_from);

                if g.ip_from < p.ip_from {
                    let seg_end = p.ip_from - 1;
                    let entry =
                        Self::make_entry(self.features, &self.opt, start, seg_end, Some(g), None);
                    let mut next_g = *g;
                    next_g.ip_from = p.ip_from;
                    self.cur_geo = Some(next_g);
                    return Some(entry);
                }
                if p.ip_from < g.ip_from {
                    let seg_end = g.ip_from - 1;
                    let entry =
                        Self::make_entry(self.features, &self.opt, start, seg_end, None, Some(p));
                    let mut next_p = *p;
                    next_p.ip_from = g.ip_from;
                    self.cur_px = Some(next_p);
                    return Some(entry);
                }

                // Overlap: g.ip_from == p.ip_from == start
                let end = g.ip_to.min(p.ip_to);
                let entry =
                    Self::make_entry(self.features, &self.opt, start, end, Some(g), Some(p));

                if g.ip_to == end {
                    self.cur_geo = self.geo_iter.next();
                } else if end < u32::MAX {
                    let mut next_g = *g;
                    next_g.ip_from = end + 1;
                    self.cur_geo = Some(next_g);
                } else {
                    self.cur_geo = None;
                }

                if p.ip_to == end {
                    self.cur_px = self.px_iter.next();
                } else if end < u32::MAX {
                    let mut next_p = *p;
                    next_p.ip_from = end + 1;
                    self.cur_px = Some(next_p);
                } else {
                    self.cur_px = None;
                }

                Some(entry)
            }
        }
    }
}

impl<G, P> Iterator for SweepLineMerger<G, P>
where
    G: Iterator<Item = RawGeoRecord>,
    P: Iterator<Item = RawPxRecord>,
{
    type Item = MergedEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        if !self.opt.coalesce {
            return self.advance_sweep();
        }

        loop {
            let next_raw = self.advance_sweep();

            match (self.pending_prev.take(), next_raw) {
                (None, None) => {
                    self.finished = true;
                    return None;
                }
                (None, Some(curr)) => {
                    self.pending_prev = Some(curr);
                }
                (Some(prev), None) => {
                    self.finished = true;
                    return Some(prev);
                }
                (Some(mut prev), Some(curr)) => {
                    if prev.ip_to < u32::MAX
                        && prev.ip_to + 1 == curr.ip_from
                        && prev.matches_attributes(&curr)
                    {
                        prev.ip_to = curr.ip_to;
                        self.pending_prev = Some(prev);
                    } else {
                        self.pending_prev = Some(curr);
                        return Some(prev);
                    }
                }
            }
        }
    }
}

/// Merged IPv6 interval entry containing unified integer-interned metadata.
/// 100% zero-heap allocation: Copy, 52 bytes, CPU cache-line friendly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MergedEntryV6 {
    pub ip_from: u128,
    pub ip_to: u128,
    pub country: [u8; 2],
    pub reg_idx: u16,
    pub city_idx: u32,
    pub isp_idx: u16,
    pub asn: u32,
    pub flags: u16,
    pub lat_fixed: i16,
    pub lon_fixed: i16,
}

impl MergedEntryV6 {
    #[inline(always)]
    pub fn matches_attributes(&self, other: &Self) -> bool {
        self.country == other.country
            && self.city_idx == other.city_idx
            && self.reg_idx == other.reg_idx
            && self.isp_idx == other.isp_idx
            && self.asn == other.asn
            && self.flags == other.flags
            && self.lat_fixed == other.lat_fixed
            && self.lon_fixed == other.lon_fixed
    }
}

/// 1D Sweep-Line Merger for IPv6 128-bit address ranges.
pub struct SweepLineMergerV6<G, P> {
    geo_iter: G,
    px_iter: P,
    cur_geo: Option<RawGeoRecordV6>,
    cur_px: Option<RawPxRecordV6>,
    pending_prev: Option<MergedEntryV6>,
    features: FeatureMask,
    opt: OptimizationConfig,
    finished: bool,
}

impl<G, P> SweepLineMergerV6<G, P>
where
    G: Iterator<Item = RawGeoRecordV6>,
    P: Iterator<Item = RawPxRecordV6>,
{
    pub fn new(
        mut geo_iter: G,
        mut px_iter: P,
        features: FeatureMask,
        opt: OptimizationConfig,
    ) -> Self {
        let cur_geo = geo_iter.next();
        let cur_px = px_iter.next();
        Self {
            geo_iter,
            px_iter,
            cur_geo,
            cur_px,
            pending_prev: None,
            features,
            opt,
            finished: false,
        }
    }

    #[inline(always)]
    fn make_entry(
        features: FeatureMask,
        opt: &OptimizationConfig,
        ip_from: u128,
        ip_to: u128,
        geo: Option<&RawGeoRecordV6>,
        px: Option<&RawPxRecordV6>,
    ) -> MergedEntryV6 {
        let country = if features.has_country() {
            geo.map(|g| g.country).unwrap_or(*b"--")
        } else {
            *b"--"
        };

        let reg_idx = if features.has_region() {
            geo.map(|g| g.reg_idx).unwrap_or(0)
        } else {
            0
        };

        let city_idx = if features.has_city() {
            geo.map(|g| g.city_idx).unwrap_or(0)
        } else {
            0
        };

        let isp_idx = if features.has_isp() {
            px.map(|p| p.isp_idx).unwrap_or(0)
        } else {
            0
        };

        let asn = if features.has_asn() {
            px.map(|p| p.asn).unwrap_or(0)
        } else {
            0
        };

        let mut flags = if features.has_threats() {
            px.map(|p| p.flags).unwrap_or(0)
        } else {
            0
        };

        if opt.collapse_threats && flags != 0 {
            flags = crate::models::GeoFlags::PROXY;
        }

        let (mut lat_fixed, mut lon_fixed) = if features.has_coords() {
            (
                geo.map(|g| g.lat_fixed).unwrap_or(0),
                geo.map(|g| g.lon_fixed).unwrap_or(0),
            )
        } else {
            (0, 0)
        };

        if opt.lossy_coords {
            lat_fixed = crate::models::quantize_coordinate(lat_fixed);
            lon_fixed = crate::models::quantize_coordinate(lon_fixed);
        }

        MergedEntryV6 {
            ip_from,
            ip_to,
            country,
            reg_idx,
            city_idx,
            isp_idx,
            asn,
            flags,
            lat_fixed,
            lon_fixed,
        }
    }

    fn advance_sweep(&mut self) -> Option<MergedEntryV6> {
        match (self.cur_geo.as_ref(), self.cur_px.as_ref()) {
            (None, None) => None,
            (Some(g), None) => {
                let entry =
                    Self::make_entry(self.features, &self.opt, g.ip_from, g.ip_to, Some(g), None);
                self.cur_geo = self.geo_iter.next();
                Some(entry)
            }
            (None, Some(p)) => {
                let entry =
                    Self::make_entry(self.features, &self.opt, p.ip_from, p.ip_to, None, Some(p));
                self.cur_px = self.px_iter.next();
                Some(entry)
            }
            (Some(g), Some(p)) => {
                if g.ip_to < p.ip_from {
                    let entry = Self::make_entry(
                        self.features,
                        &self.opt,
                        g.ip_from,
                        g.ip_to,
                        Some(g),
                        None,
                    );
                    self.cur_geo = self.geo_iter.next();
                    return Some(entry);
                }
                if p.ip_to < g.ip_from {
                    let entry = Self::make_entry(
                        self.features,
                        &self.opt,
                        p.ip_from,
                        p.ip_to,
                        None,
                        Some(p),
                    );
                    self.cur_px = self.px_iter.next();
                    return Some(entry);
                }

                let start = g.ip_from.min(p.ip_from);

                if g.ip_from < p.ip_from {
                    let seg_end = p.ip_from - 1;
                    let entry =
                        Self::make_entry(self.features, &self.opt, start, seg_end, Some(g), None);
                    let mut next_g = *g;
                    next_g.ip_from = p.ip_from;
                    self.cur_geo = Some(next_g);
                    return Some(entry);
                }
                if p.ip_from < g.ip_from {
                    let seg_end = g.ip_from - 1;
                    let entry =
                        Self::make_entry(self.features, &self.opt, start, seg_end, None, Some(p));
                    let mut next_p = *p;
                    next_p.ip_from = g.ip_from;
                    self.cur_px = Some(next_p);
                    return Some(entry);
                }

                // Overlap
                let end = g.ip_to.min(p.ip_to);
                let entry =
                    Self::make_entry(self.features, &self.opt, start, end, Some(g), Some(p));

                if g.ip_to == end {
                    self.cur_geo = self.geo_iter.next();
                } else if end < u128::MAX {
                    let mut next_g = *g;
                    next_g.ip_from = end + 1;
                    self.cur_geo = Some(next_g);
                } else {
                    self.cur_geo = None;
                }

                if p.ip_to == end {
                    self.cur_px = self.px_iter.next();
                } else if end < u128::MAX {
                    let mut next_p = *p;
                    next_p.ip_from = end + 1;
                    self.cur_px = Some(next_p);
                } else {
                    self.cur_px = None;
                }

                Some(entry)
            }
        }
    }
}

impl<G, P> Iterator for SweepLineMergerV6<G, P>
where
    G: Iterator<Item = RawGeoRecordV6>,
    P: Iterator<Item = RawPxRecordV6>,
{
    type Item = MergedEntryV6;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        if !self.opt.coalesce {
            return self.advance_sweep();
        }

        loop {
            let next_raw = self.advance_sweep();

            match (self.pending_prev.take(), next_raw) {
                (None, None) => {
                    self.finished = true;
                    return None;
                }
                (None, Some(curr)) => {
                    self.pending_prev = Some(curr);
                }
                (Some(prev), None) => {
                    self.finished = true;
                    return Some(prev);
                }
                (Some(mut prev), Some(curr)) => {
                    if prev.ip_to < u128::MAX
                        && prev.ip_to + 1 == curr.ip_from
                        && prev.matches_attributes(&curr)
                    {
                        prev.ip_to = curr.ip_to;
                        self.pending_prev = Some(prev);
                    } else {
                        self.pending_prev = Some(curr);
                        return Some(prev);
                    }
                }
            }
        }
    }
}
