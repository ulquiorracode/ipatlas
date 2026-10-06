use ipatlas_core::compiler::StringPool;
use ipatlas_core::{DatasetIngestionAdapter, IngestRecordV4, IngestRecordV6};

#[test]
fn test_spi_cidr_parsing_v4() {
    let rec = IngestRecordV4::from_cidr("192.168.1.0/24").expect("valid cidr");
    assert_eq!(rec.ip_from, 0xC0A80100);
    assert_eq!(rec.ip_to, 0xC0A801FF);

    let rec32 = IngestRecordV4::from_cidr("10.0.0.1/32").expect("valid host");
    assert_eq!(rec32.ip_from, 0x0A000001);
    assert_eq!(rec32.ip_to, 0x0A000001);

    assert!(IngestRecordV4::from_cidr("invalid/33").is_err());
    assert!(IngestRecordV4::from_cidr("999.0.0.1/24").is_err());
}

#[test]
fn test_spi_cidr_parsing_v6() {
    let rec = IngestRecordV6::from_cidr("2001:db8::/32").expect("valid cidr v6");
    assert_eq!(rec.ip_from, 0x20010db8000000000000000000000000);
    assert_eq!(rec.ip_to, 0x20010db8ffffffffffffffffffffffff);

    assert!(IngestRecordV6::from_cidr("::1/129").is_err());
}

#[test]
fn test_spi_into_raw_pair_conversion() {
    let mut rec = IngestRecordV4::from_cidr("8.8.8.0/24").unwrap();
    rec.country = *b"US";
    rec.city = Some("Mountain View".into());
    rec.region = Some("California".into());
    rec.isp = Some("Google LLC".into());
    rec.asn = 15169;
    rec.latitude = 37.42;
    rec.longitude = -122.08;
    rec.flags = 0x0004;

    let mut cities = StringPool::new();
    let mut regions = StringPool::new();
    let mut isps = StringPool::new();

    let (geo, px) = rec.into_raw_pair(&mut cities, &mut regions, &mut isps, true);

    assert_eq!(geo.country, *b"US");
    assert_eq!(geo.lat_fixed, 3742);
    assert_eq!(geo.lon_fixed, -12208);
    assert_eq!(px.asn, 15169);
    assert_eq!(px.flags, 0x0004);
}

struct StaticFeedAdapter {
    entries: Vec<IngestRecordV4>,
}

impl DatasetIngestionAdapter for StaticFeedAdapter {
    fn parse_v4(&mut self) -> Box<dyn Iterator<Item = IngestRecordV4> + '_> {
        Box::new(self.entries.drain(..))
    }
}

#[test]
fn test_custom_spi_adapter_iteration() {
    let mut adapter = StaticFeedAdapter {
        entries: vec![
            IngestRecordV4::from_cidr("1.1.1.0/24").unwrap(),
            IngestRecordV4::from_cidr("1.0.0.0/24").unwrap(),
        ],
    };

    let items: Vec<_> = adapter.parse_v4().collect();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].ip_from, 0x01010100);
    assert_eq!(items[1].ip_from, 0x01000000);
}
