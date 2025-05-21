use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::Context;
use github_actions_models::common::{RepositoryUses, Uses};
use serde::Deserialize;

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::finding::{Confidence, Finding, Persona, Severity};
use crate::models::uses::RepositoryUsesPattern;
use crate::models::{CompositeStep, Step, StepCommon, uses::UsesExt as _};

pub(crate) struct UnpinnedUses {
    policies: UnpinnedUsesPolicies,
    /// Combined set of official orgs and additional allowlisted orgs
    allowed_orgs: HashSet<String>,
}

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

// Define a constant for the special message we'll look for in the TPA list formatter
pub(crate) const THIRD_PARTY_MESSAGE: &str = "third-party action is not pinned to a commit SHA";

// Default official GitHub organizations that are considered trusted
const DEFAULT_OFFICIAL_ORGS: &[&str] = &["actions", "github", "dependabot"];

impl UnpinnedUses {
    pub fn evaluate_pinning(&self, uses: &Uses) -> Option<(String, Severity, Persona)> {
        match uses {
            // Don't evaluate pinning for local `uses:`, since unpinned references
            // are fully controlled by the repository anyways.
            Uses::Local(_) => None,
            // We don't have detailed policies for `uses: docker://` yet,
            // in part because evaluating the risk of a tagged versus hash-pinned
            // Docker image depends on the image and its registry).
            //
            // Instead, we produce a blanket finding for unpinned images,
            // and a pedantic-only finding for unhashed images.
            Uses::Docker(_) => {
                if uses.unpinned() {
                    Some((
                        "action is not pinned to a tag, branch, or hash ref".into(),
                        Severity::Medium,
                        Persona::default(),
                    ))
                } else if uses.unhashed() {
                    Some((
                        "action is not pinned to a hash".into(),
                        Severity::Low,
                        Persona::Pedantic,
                    ))
                } else {
                    None
                }
            }
            Uses::Repository(repo_uses) => {
                // Check if this is a third-party action (not from allowlisted orgs)
                let is_third_party = !self.allowed_orgs.contains(&repo_uses.owner.to_lowercase());
                
                // For third-party actions that aren't hash pinned, we use our special message
                if is_third_party && uses.unhashed() {
                    return Some((
                        THIRD_PARTY_MESSAGE.into(),
                        Severity::High,
                        Persona::default(),
                    ));
                }
                
                let (pattern, policy) = self.policies.get_policy(repo_uses);

                let pat_desc = match pattern {
                    Some(RepositoryUsesPattern::Any) | None => "blanket".into(),
                    Some(RepositoryUsesPattern::InOwner(owner)) => format!("{owner}/*"),
                    Some(RepositoryUsesPattern::InRepo { owner, repo }) => {
                        format!("{owner}/{repo}/*")
                    }
                    Some(RepositoryUsesPattern::ExactRepo { owner, repo }) => {
                        format!("{owner}/{repo}")
                    }
                    Some(RepositoryUsesPattern::ExactPath {
                        owner,
                        repo,
                        subpath,
                    }) => {
                        format!("{owner}/{repo}/{subpath}")
                    }
                    // Not allowed in this audit.
                    Some(RepositoryUsesPattern::ExactWithRef { .. }) => unreachable!(),
                };

                match policy {
                    UsesPolicy::Any => None,
                    UsesPolicy::RefPin => uses.unpinned().then_some((
                        format!(
                            "action is not pinned to a ref or hash (required by {pat_desc} policy)"
                        ),
                        Severity::High,
                        Persona::default(),
                    )),
                    UsesPolicy::HashPin => {
                        if uses.unhashed() && !is_third_party { // We've already handled third-party actions above
                            Some((
                                format!("action is not pinned to a hash (required by {pat_desc} policy)"),
                                Severity::High,
                                Persona::default(),
                            ))
                        } else {
                            None
                        }
                    }
                }
            }
        }
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(findings);
        };

        if let Some((annotation, severity, persona)) = self.evaluate_pinning(uses) {
            findings.push(
                Self::finding()
                    .confidence(Confidence::High)
                    .severity(severity)
                    .persona(persona)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated(annotation),
                    )
                    .build(step)?,
            );
        };

        Ok(findings)
    }
}

// Update the Audit implementation in unpinned_uses.rs

impl Audit for UnpinnedUses {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        let config = state
            .config
            .rule_config::<UnpinnedUsesConfig>(Self::ident())
            .context("invalid configuration")
            .map_err(AuditLoadError::Fail)?
            .unwrap_or_default();

        // Create the default set of allowed orgs
        let mut allowed_orgs = DEFAULT_OFFICIAL_ORGS
            .iter()
            .map(|s| s.to_string().to_lowercase())
            .collect::<HashSet<String>>();
        
        // Add allowlisted orgs from file if specified via CLI
        if let Some(allowlist_path) = &state.tpa_allowlist_file {
            match fs::read_to_string(allowlist_path) {
                Ok(contents) => {
                    for line in contents.lines() {
                        let trimmed = line.trim();
                        // Skip empty lines and comments
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            allowed_orgs.insert(trimmed.to_lowercase());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read allowlist file {}: {}", allowlist_path, e);
                }
            }
        }
        
        // Add explicitly specified orgs from CLI
        if let Some(additional_orgs) = &state.tpa_allowed_org {
            for org in additional_orgs {
                allowed_orgs.insert(org.to_lowercase());
            }
        }
        
        // Add any additional orgs specified in the config file
        if let Some(allowlist_path) = &config.allowlist_file {
            match fs::read_to_string(allowlist_path) {
                Ok(contents) => {
                    for line in contents.lines() {
                        let trimmed = line.trim();
                        // Skip empty lines and comments
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            allowed_orgs.insert(trimmed.to_lowercase());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read config allowlist file {}: {}", allowlist_path, e);
                }
            }
        }
        
        // Add any additional orgs specified in the config
        if let Some(additional_orgs) = &config.additional_allowed_orgs {
            for org in additional_orgs {
                allowed_orgs.insert(org.to_lowercase());
            }
        }

        let policies = UnpinnedUsesPolicies::try_from(config)
            .context("invalid configuration")
            .map_err(AuditLoadError::Fail)?;

        Ok(Self { 
            policies,
            allowed_orgs,
        })
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        self.process_step(step)
    }
}

/// Config for the `unpinned-uses` rule.
///
/// This configuration is reified into an `UnpinnedUsesPolicies`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct UnpinnedUsesConfig {
    /// A mapping of `uses:` patterns to policies.
    policies: HashMap<RepositoryUsesPattern, UsesPolicy>,
    
    /// Path to a file containing additional orgs/users to treat as trusted
    /// Each line in the file should contain one org/user name
    #[serde(default)]
    allowlist_file: Option<String>,
    
    /// Additional allowed organizations to consider as trusted beyond the defaults
    #[serde(default)]
    additional_allowed_orgs: Option<Vec<String>>,
}

impl Default for UnpinnedUsesConfig {
    fn default() -> Self {
        Self {
            policies: [
                (
                    RepositoryUsesPattern::InOwner("actions".into()),
                    UsesPolicy::RefPin,
                ),
                (
                    RepositoryUsesPattern::InOwner("github".into()),
                    UsesPolicy::RefPin,
                ),
                (
                    RepositoryUsesPattern::InOwner("dependabot".into()),
                    UsesPolicy::RefPin,
                ),
                (RepositoryUsesPattern::Any, UsesPolicy::HashPin),
            ]
            .into(),
            allowlist_file: None,
            additional_allowed_orgs: None,
        }
    }
}

/// A singular policy for a `uses:` reference.
#[derive(Copy, Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum UsesPolicy {
    /// No policy; all `uses:` references are allowed, even unpinned ones.
    Any,
    /// `uses:` references must be pinned to a tag, branch, or hash ref.
    RefPin,
    /// `uses:` references must be pinned to a hash ref.
    HashPin,
}

/// Represents the set of policies used to evaluate `uses:` references.
struct UnpinnedUsesPolicies {
    /// The policy tree is a mapping of `owner` slugs to a list of
    /// `(pattern, policy)` pairs under that owner, ordered by specificity.
    ///
    /// For example, a config containing both `foo/*: hash-pin` and
    /// `foo/bar: ref-pin` would produce a policy tree like this:
    ///
    /// ```text
    /// foo:
    ///   - foo/bar: ref-pin
    ///   - foo/*: hash-pin
    /// ```
    ///
    /// This is done for performance reasons: a two-level structure here
    /// means that checking a `uses:` is a linear scan of the policies
    /// for that owner, rather than a full scan of all policies.
    policy_tree: HashMap<String, Vec<(RepositoryUsesPattern, UsesPolicy)>>,

    /// This is the policy that's applied if nothing in the policy tree matches.
    ///
    /// Normally is this configured by an `*` entry in the config or by
    /// `UnpinnedUsesConfig::default()`. However, if the user explicitly
    /// omits a `*` rule, this will be `UsesPolicy::HashPin`.
    default_policy: UsesPolicy,
}

impl UnpinnedUsesPolicies {
    /// Returns the most specific policy for the given repository `uses` reference,
    /// or the default policy if none match.
    fn get_policy(&self, uses: &RepositoryUses) -> (Option<&RepositoryUsesPattern>, UsesPolicy) {
        match self.policy_tree.get(&uses.owner) {
            Some(policies) => {
                // Policies are ordered by specificity, so we can
                // iterate and return eagerly.
                for (uses_pattern, policy) in policies {
                    if uses_pattern.matches(uses) {
                        return (Some(uses_pattern), *policy);
                    }
                }
                // The policies under `owner/` might be fully divergent
                // if there isn't an `owner/*` rule, so we fall back
                // to the default policy.
                (None, self.default_policy)
            }
            None => (None, self.default_policy),
        }
    }
}

impl TryFrom<UnpinnedUsesConfig> for UnpinnedUsesPolicies {
    type Error = anyhow::Error;

    fn try_from(config: UnpinnedUsesConfig) -> Result<Self, Self::Error> {
        let mut policy_tree: HashMap<String, Vec<(RepositoryUsesPattern, UsesPolicy)>> =
            HashMap::new();
        let mut default_policy = UsesPolicy::HashPin;

        for (pattern, policy) in config.policies {
            match &pattern {
                // Patterns with refs don't make sense in this context, since
                // we're establishing policies for the refs themselves.
                RepositoryUsesPattern::ExactWithRef { .. } => {
                    return Err(anyhow::anyhow!("can't use exact ref patterns here"));
                }
                RepositoryUsesPattern::ExactPath { owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::ExactRepo { owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::InRepo { owner, .. } => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::InOwner(owner) => {
                    policy_tree
                        .entry(owner.clone())
                        .or_default()
                        .push((pattern, policy));
                }
                RepositoryUsesPattern::Any => {
                    default_policy = policy;
                }
            }
        }

        // Sort the policies for each owner by specificity.
        for policies in policy_tree.values_mut() {
            policies.sort_by(|a, b| a.0.cmp(&b.0));
        }

        Ok(Self {
            policy_tree,
            default_policy,
        })
    }
}