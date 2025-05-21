// Fixed tpa_list.rs without requiring Clone

//! Format for listing third-party actions not pinned to commit SHAs.
//! Can output either a simple text list or a comprehensive JSON report.

use std::collections::HashSet;
use std::io;
use std::fs::File;

use anyhow::Result;
use serde::Serialize;

use crate::finding::Finding;
use crate::audit::unpinned_uses::THIRD_PARTY_MESSAGE;

/// An action extracted from a workflow file
#[derive(Debug, Serialize, Clone)]  // Added explicit Clone derive
struct Action {
    /// The action reference (e.g., "actions/checkout@v3")
    reference: String,
    /// Whether the action is pinned to a commit SHA
    pinned_to_sha: bool,
    /// Whether the action is from a third party (non-trusted organization)
    third_party: bool,
    /// Full line where the action is defined
    line: String,
    /// File path where the action is defined
    file_path: String,
}

/// Report structure for JSON output
#[derive(Debug, Serialize)]
struct ActionReport {
    /// All actions found in the repository
    actions: Vec<Action>,
    /// Summary statistics
    summary: Summary,
}

/// Summary statistics for the report
#[derive(Debug, Serialize)]
struct Summary {
    /// Total number of actions found
    total_actions: usize,
    /// Number of unpinned third-party actions
    unpinned_third_party: usize,
    /// Number of pinned third-party actions
    pinned_third_party: usize,
    /// Number of official/trusted actions
    official_actions: usize,
}

/// Extracts action data from findings
fn extract_actions(findings: &[Finding]) -> Vec<Action> {
    let mut actions = Vec::new();
    
    // Map to keep track of all unique action references we've seen
    let mut seen_refs = HashSet::new();
    
    // First, collect all unpinned third-party actions
    let unpinned_findings = findings.iter()
        .filter(|f| f.ident == "unpinned-uses")
        .filter(|f| {
            // Look for our special marker in the annotation
            f.locations.iter().any(|loc| {
                loc.symbolic.annotation == THIRD_PARTY_MESSAGE
            })
        });

    for finding in unpinned_findings {
        // Get the primary location, which should contain the action reference
        if let Some(location) = finding.locations.iter().find(|loc| loc.symbolic.is_primary()) {
            let file_path = location.symbolic.key.presentation_path().to_string();
            
            // Extract the uses line from the feature text
            if let Some(action_ref) = extract_uses_reference(&location.concrete.feature) {
                let action = Action {
                    reference: action_ref.clone(),
                    pinned_to_sha: false,
                    third_party: true,
                    line: location.concrete.feature.trim().to_string(),
                    file_path: file_path.clone(),
                };
                
                // Only add if we haven't seen this exact action reference before
                let key = (file_path.clone(), action_ref.clone());
                if !seen_refs.contains(&key) {
                    seen_refs.insert(key);
                    actions.push(action);
                }
            }
        }
    }
    
    // Next, collect all other uses: references
    // This includes official actions and pinned third-party actions
    let other_findings = findings.iter()
        .filter(|f| f.ident == "unpinned-uses")
        .filter(|f| {
            // Exclude the ones we already processed
            !f.locations.iter().any(|loc| {
                loc.symbolic.annotation == THIRD_PARTY_MESSAGE
            })
        });

    for finding in other_findings {
        if let Some(location) = finding.locations.iter().find(|loc| loc.symbolic.is_primary()) {
            let file_path = location.symbolic.key.presentation_path().to_string();
            
            if let Some(action_ref) = extract_uses_reference(&location.concrete.feature) {
                let is_third_party = !is_official_action(&action_ref);
                let is_pinned = action_ref.contains('@') && 
                               (action_ref.matches('@').count() == 1) && 
                               is_likely_sha(action_ref.split('@').nth(1).unwrap_or(""));
                
                let action = Action {
                    reference: action_ref.clone(),
                    pinned_to_sha: is_pinned,
                    third_party: is_third_party,
                    line: location.concrete.feature.trim().to_string(),
                    file_path: file_path.clone(),
                };
                
                // Only add if we haven't seen this exact action reference before
                let key = (file_path.clone(), action_ref.clone());
                if !seen_refs.contains(&key) {
                    seen_refs.insert(key);
                    actions.push(action);
                }
            }
        }
    }
    
    actions
}

/// Check if an action reference is likely from an official organization
fn is_official_action(action_ref: &str) -> bool {
    // Extract the organization from "org/repo@ref"
    let org = action_ref.split('/').next().unwrap_or("");
    
    // Check if it's one of the official orgs
    matches!(org.to_lowercase().as_str(), "actions" | "github" | "dependabot")
}

/// Check if a string is likely a git SHA (at least 40 hex chars)
fn is_likely_sha(s: &str) -> bool {
    s.len() >= 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Generate summary statistics
fn generate_summary(actions: &[Action]) -> Summary {
    let total_actions = actions.len();
    let unpinned_third_party = actions.iter()
        .filter(|a| a.third_party && !a.pinned_to_sha)
        .count();
    let pinned_third_party = actions.iter()
        .filter(|a| a.third_party && a.pinned_to_sha)
        .count();
    let official_actions = actions.iter()
        .filter(|a| !a.third_party)
        .count();
        
    Summary {
        total_actions,
        unpinned_third_party,
        pinned_third_party,
        official_actions,
    }
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

/// Output the TPA list in the requested format.
/// 
/// If the --format=tpa-list flag is used, a simple text list is output.
/// Additionally, a JSON report is always saved to all_actions.json.
pub(crate) fn output(sink: impl io::Write, findings: &[Finding]) -> Result<()> {
    let mut sink = sink;
    
    // Extract all actions from the findings
    let all_actions = extract_actions(findings);
    
    // Generate summary
    let summary = generate_summary(&all_actions);
    
    // Create the full report
    let report = ActionReport {
        actions: all_actions,  // No need to clone now that Action implements Clone
        summary,
    };
    
    // Save the JSON report
    let json_file = File::create("all_actions.json")?;
    serde_json::to_writer_pretty(json_file, &report)?;
    
    // Output the simple TPA list to the command output
    for action in &report.actions {
        if action.third_party && !action.pinned_to_sha {
            writeln!(sink, "{}: uses: {}", action.file_path, action.reference)?;
        }
    }
    
    Ok(())
}