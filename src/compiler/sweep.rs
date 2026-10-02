use crate::compiler::parser::{RawGeoRecord, RawPxRecord};
use crate::models::{FeatureMask, OptimizationConfig};

/// Merged interval entry containing unified metadata from Geo and Proxy datasets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergedEntry {
    pub ip_from: u32,
    pub ip_to: u32,
    pub country: [u8; 2],
    pub region: String,
    pub city: String,
    pub isp: String,
    pub asn: u32,
    pub flags: u16,
    pub lat_fixed: i16,
    pub lon_fixed: i16,
}

impl MergedEntry {
    /// Compares metadata attributes for coalescing adjacent intervals.
    #[inline]
    pub fn matches_attributes(&self, other: &Self) -> bool {
        self.country == other.country
            && self.asn == other.asn
            && self.flags == other.flags
            && self.lat_fixed == other.lat_fixed
            && self.lon_fixed == other.lon_fixed
            && self.region == other.region
            && self.city == other.city
            && self.isp == other.isp
    }
}

/// 1D Sweep-Line Merger with on-the-fly Interval Coalescing.
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

    #[inline]
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

        let mut region = if features.has_region() {
            geo.map(|g| g.region.clone()).unwrap_or_default()
        } else {
            String::new()
        };

        let mut city = if features.has_city() {
            geo.map(|g| g.city.clone()).unwrap_or_default()
        } else {
            String::new()
        };

        let mut isp = if features.has_isp() {
            px.map(|p| p.isp.clone()).unwrap_or_default()
        } else {
            String::new()
        };

        if opt.normalize_strings {
            region = region.trim().to_string();
            city = city.trim().to_string();
            isp = isp.trim().to_string();
        }

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
            // Quantize fixed coordinates to 1 decimal place (~10km)
            lat_fixed = (lat_fixed / 10) * 10;
            lon_fixed = (lon_fixed / 10) * 10;
        }

        MergedEntry {
            ip_from,
            ip_to,
            country,
            region,
            city,
            isp,
            asn,
            flags,
            lat_fixed,
            lon_fixed,
        }
    }

    /// Pulls the next raw uncoalesced interval from the sweep line.
    fn next_raw_interval(&mut self) -> Option<MergedEntry> {
        let features = self.features;
        let opt = &self.opt;

        match (&mut self.cur_geo, &mut self.cur_px) {
            (Some(g), None) => {
                let entry = Self::make_entry(features, opt, g.ip_from, g.ip_to, Some(g), None);
                self.cur_geo = self.geo_iter.next();
                Some(entry)
            }
            (None, Some(p)) => {
                let entry = Self::make_entry(features, opt, p.ip_from, p.ip_to, None, Some(p));
                self.cur_px = self.px_iter.next();
                Some(entry)
            }
            (Some(g), Some(p)) => {
                if g.ip_to < p.ip_from {
                    // Geo strictly precedes PX
                    let entry = Self::make_entry(features, opt, g.ip_from, g.ip_to, Some(g), None);
                    self.cur_geo = self.geo_iter.next();
                    Some(entry)
                } else if p.ip_to < g.ip_from {
                    // PX strictly precedes Geo
                    let entry = Self::make_entry(features, opt, p.ip_from, p.ip_to, None, Some(p));
                    self.cur_px = self.px_iter.next();
                    Some(entry)
                } else {
                    // Intervals overlap
                    if g.ip_from < p.ip_from {
                        let end = p.ip_from - 1;
                        let entry = Self::make_entry(features, opt, g.ip_from, end, Some(g), None);
                        g.ip_from = p.ip_from;
                        return Some(entry);
                    } else if p.ip_from < g.ip_from {
                        let end = g.ip_from - 1;
                        let entry = Self::make_entry(features, opt, p.ip_from, end, None, Some(p));
                        p.ip_from = g.ip_from;
                        return Some(entry);
                    }

                    // Now g.ip_from == p.ip_from
                    let overlap_end = g.ip_to.min(p.ip_to);
                    let entry =
                        Self::make_entry(features, opt, g.ip_from, overlap_end, Some(g), Some(p));

                    if g.ip_to == overlap_end {
                        self.cur_geo = self.geo_iter.next();
                    } else if overlap_end < u32::MAX {
                        g.ip_from = overlap_end + 1;
                    } else {
                        self.cur_geo = None;
                    }

                    if p.ip_to == overlap_end {
                        self.cur_px = self.px_iter.next();
                    } else if overlap_end < u32::MAX {
                        p.ip_from = overlap_end + 1;
                    } else {
                        self.cur_px = None;
                    }

                    Some(entry)
                }
            }
            (None, None) => None,
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
            return self.next_raw_interval();
        }

        // On-the-fly Interval Coalescing
        while let Some(curr) = self.next_raw_interval() {
            match self.pending_prev.take() {
                Some(mut prev) => {
                    if prev.ip_to < u32::MAX
                        && prev.ip_to + 1 == curr.ip_from
                        && prev.matches_attributes(&curr)
                    {
                        // Coalesce! Extend previous interval end
                        prev.ip_to = curr.ip_to;
                        self.pending_prev = Some(prev);
                    } else {
                        // Cannot coalesce, yield prev and store curr
                        self.pending_prev = Some(curr);
                        return Some(prev);
                    }
                }
                None => {
                    self.pending_prev = Some(curr);
                }
            }
        }

        // Emit final pending record
        if let Some(final_rec) = self.pending_prev.take() {
            self.finished = true;
            return Some(final_rec);
        }

        self.finished = true;
        None
    }
}
