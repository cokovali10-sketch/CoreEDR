use coreedr::ml::features::{extract_features_from_bytes, FeatureVector};

#[test]
fn test_feature_vector_to_array() {
    let fv = FeatureVector {
        entropy: 5.0,
        file_size: 1000,
        string_ratio: 0.5,
        import_count: 2,
        section_count: 1,
        has_debug_info: false,
        has_overlay: false,
        timestamp_anomaly: false,
        high_entropy_sections: 0,
        suspicious_imports: 0,
        pe_characteristics: 0,
        subsystem: 0,
        dll_characteristics: 0,
        compilation_timestamp: 0,
        rich_header_present: false,
        tls_callbacks: 0,
        resources_count: 0,
        avg_section_entropy: 4.0,
        max_section_entropy: 5.0,
        suspicious_strings_count: 2,
    };
    let arr = fv.to_array();
    assert_eq!(arr.len(), 20);
}

#[test]
fn test_feature_names() {
    let names = FeatureVector::feature_names();
    assert_eq!(names.len(), 20);
}

#[test]
fn test_extract_features_from_bytes() {
    let data = vec![0u8; 256];
    let fv = extract_features_from_bytes(&data).unwrap();
    assert!(fv.entropy >= 0.0);
}
