// Create a new file: crates/zizmor/src/output/tpa_list.rs

//! Format for listing third-party actions not pinned to commit SHAs.

use std::io;

use anyhow::Result;

use crate::finding::Finding;
use crate::audit::unpinned_uses::THIRD_PARTY_MESSAGE;

/// Output a simple list of third-party actions not pinned to commit SHAs.
/// 
/// This format shows just the file path and the specific `uses:` reference.
pub(crate) fn output(sink: impl io::Write, findings: &[Finding]) -> Result<()> {
    let mut sink = sink;

    // Filter to keep only unpinned-uses findings with our specific message
    let tpa_findings = findings.iter()
        .filter(|f| f.ident == "unpinned-uses")
        .filter(|f| {
            // Look for our special marker in the annotation
            f.locations.iter().any(|loc| {
                loc.symbolic.annotation == THIRD_PARTY_MESSAGE
            })
        });

    for finding in tpa_findings {
        // Get the primary location, which should contain the action reference
        if let Some(location) = finding.locations.iter().find(|loc| loc.symbolic.is_primary()) {
            let file_path = location.symbolic.key.presentation_path();
            
            // Extract the uses line from the feature text
            if let Some(uses_ref) = extract_uses_reference(&location.concrete.feature) {
                writeln!(sink, "{}: uses: {}", file_path, uses_ref)?;
            }
        }
    }

    Ok(())
}

/// Extracts the action reference from a uses string
fn extract_uses_reference(feature: &str) -> Option<String> {
    // Common patterns:
    // "uses: org/repo@ref" or just "org/repo@ref"
    
    // Look for common patterns in the feature text
    if let Some(idx) = feature.find("uses:") {
        let rest = &feature[idx + 5..].trim();
        return Some(rest.to_string());
    }
    
    // Try to find a pattern that looks like org/repo@ref
    let parts: Vec<&str> = feature.split_whitespace().collect();
    for part in parts {
        if part.contains('/') && (part.contains('@') || !part.contains(':')) {
            return Some(part.trim().to_string());
        }
    }
    
    // If we can't extract it nicely, just return the whole trimmed feature
    Some(feature.trim().to_string())
}