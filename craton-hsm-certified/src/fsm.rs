// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Craton Software Company
//! Finite State Model (FSM) validation for FIPS 140-3.
//!
//! Models the required module states and transitions per FIPS 140-3 / ISO
//! 19790. Provides validation that the state machine is well-formed:
//! - all states are reachable from the initial state
//! - no dead states (except the terminal `PowerOff`)
//! - SelfTest is mandatory after PowerOn (and is the *only* outgoing
//!   transition from PowerOn)
//! - ErrorState may only transition to Zeroization or PowerOff
//! - operational states (`CryptoOfficerMode`, `UserMode`) **may not**
//!   transition directly to PowerOff — they must first pass through
//!   Zeroization (FIPS 140-3 §7.9 zeroization-on-shutdown requirement).

use crate::error::{CertError, CertResult};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// FIPS 140-3 module states.
///
/// The `#[repr(u8)]` discriminant is **the canonical numeric encoding** used
/// by the atomic-state machinery in [`ModuleFsm`]; both [`state_to_u8`] and
/// [`u8_to_state`] derive from `as u8` so the enum order and the byte
/// mapping cannot drift out of sync (the M5 audit finding fixed in this
/// pass: previously `state_to_u8` mapped `Zeroization -> 5` while the enum
/// itself made `ErrorState = 5`, so the atomic-stored byte for a state
/// silently meant a different state when read back).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleState {
    /// Module is powered down; no cryptographic services are available.
    PowerOff = 0,
    /// Initial post-boot state, prior to running self-tests.
    PowerOn = 1,
    /// Module is executing the FIPS 140-3 power-on self-tests (KATs).
    SelfTest = 2,
    /// Crypto Officer is authenticated; administrative services are available.
    CryptoOfficerMode = 3,
    /// User role authenticated; approved cryptographic services are available.
    UserMode = 4,
    /// Self-test or operational error has placed the module in a fail state.
    ErrorState = 5,
    /// CSPs are being actively zeroised; only transitions to `PowerOff`.
    Zeroization = 6,
}

const STATE_COUNT: usize = 7;

impl ModuleState {
    /// All defined states.
    pub fn all() -> &'static [ModuleState] {
        &[
            Self::PowerOff,
            Self::PowerOn,
            Self::SelfTest,
            Self::CryptoOfficerMode,
            Self::UserMode,
            Self::ErrorState,
            Self::Zeroization,
        ]
    }

    /// Label suitable for DOT graph output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::PowerOff => "Power Off",
            Self::PowerOn => "Power On",
            Self::SelfTest => "Self-Test",
            Self::CryptoOfficerMode => "Crypto Officer",
            Self::UserMode => "User Mode",
            Self::ErrorState => "Error",
            Self::Zeroization => "Zeroization",
        }
    }

    /// DOT node identifier (no spaces).
    fn dot_id(&self) -> &'static str {
        match self {
            Self::PowerOff => "PowerOff",
            Self::PowerOn => "PowerOn",
            Self::SelfTest => "SelfTest",
            Self::CryptoOfficerMode => "CryptoOfficer",
            Self::UserMode => "UserMode",
            Self::ErrorState => "ErrorState",
            Self::Zeroization => "Zeroization",
        }
    }

    #[inline]
    fn idx(&self) -> usize {
        *self as usize
    }
}

/// A single state transition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FsmTransition {
    /// Source state.
    pub from: ModuleState,
    /// Destination state.
    pub to: ModuleState,
    /// Event name that triggers the transition.
    pub event: String,
    /// Optional guard expression that must be satisfied for the transition to fire.
    pub guard: Option<String>,
}

/// Finite state model for a FIPS 140-3 module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsmModel {
    /// Full transition table.
    pub transitions: Vec<FsmTransition>,
    /// Starting state when the module is powered on.
    pub initial_state: ModuleState,
}

impl FsmModel {
    /// Look up the next state given the current state and an event name.
    /// Returns the destination state if the transition exists.
    ///
    /// # Warning
    ///
    /// This does NOT evaluate guards. Use [`FsmModel::transition`] for
    /// guard-checked transitions — the audit finding M1 was that callers of
    /// `next_state` could silently bypass `all_kats_pass` and similar guards.
    pub fn next_state(&self, current: ModuleState, event: &str) -> Option<ModuleState> {
        self.transitions
            .iter()
            .find(|t| t.from == current && t.event == event)
            .map(|t| t.to)
    }

    /// Attempt a transition, consulting the guard predicate for any
    /// transition with a named guard. Returns the destination state on
    /// success; returns an error on a missing transition or a failed guard.
    ///
    /// `guard_eval` is called once per named guard encountered. It receives
    /// the guard name and must return `true` iff the guard is satisfied.
    /// Guards whose predicate is unknown to the caller should return `false`
    /// so the transition fails closed.
    pub fn transition<F>(
        &self,
        current: ModuleState,
        event: &str,
        mut guard_eval: F,
    ) -> Result<ModuleState, FsmTransitionError>
    where
        F: FnMut(&str) -> bool,
    {
        let t = self
            .transitions
            .iter()
            .find(|t| t.from == current && t.event == event)
            .ok_or(FsmTransitionError::NoSuchTransition {
                from: current,
                event: event.to_string(),
            })?;
        if let Some(guard) = &t.guard {
            if !guard_eval(guard) {
                return Err(FsmTransitionError::GuardFailed {
                    from: current,
                    to: t.to,
                    event: event.to_string(),
                    guard: guard.clone(),
                });
            }
        }
        Ok(t.to)
    }
}

/// Failure modes from a guard-checking [`FsmModel::transition`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmTransitionError {
    /// The event is not declared out of the current state.
    NoSuchTransition {
        /// State the FSM was in when the event arrived.
        from: ModuleState,
        /// Name of the event that had no matching transition.
        event: String,
    },
    /// The transition exists but its guard predicate returned `false`.
    GuardFailed {
        /// State the FSM was in when the event arrived.
        from: ModuleState,
        /// Destination the transition would have moved to had the guard passed.
        to: ModuleState,
        /// Name of the event whose guard rejected the transition.
        event: String,
        /// Name of the guard predicate that failed.
        guard: String,
    },
}

impl std::fmt::Display for FsmTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchTransition { from, event } => {
                write!(f, "FSM: no transition from {from:?} on event '{event}'")
            }
            Self::GuardFailed {
                from,
                to,
                event,
                guard,
            } => write!(
                f,
                "FSM: transition {from:?} -> {to:?} on '{event}' blocked by guard [{guard}]"
            ),
        }
    }
}

impl std::error::Error for FsmTransitionError {}

// ---------------------------------------------------------------------------
// Default FIPS FSM
// ---------------------------------------------------------------------------

/// Construct the default FIPS 140-3 compliant state machine for a Level 1
/// software module.
///
/// Notable properties:
/// - PowerOn → SelfTest is the **only** transition out of PowerOn.
/// - Operational states cannot reach PowerOff without going through
///   Zeroization first.
/// - ErrorState exits to Zeroization or PowerOff only.
pub fn default_fips_fsm() -> FsmModel {
    FsmModel {
        initial_state: ModuleState::PowerOff,
        transitions: vec![
            // Power on
            FsmTransition {
                from: ModuleState::PowerOff,
                to: ModuleState::PowerOn,
                event: "power_on".to_string(),
                guard: None,
            },
            // PowerOn must go through SelfTest
            FsmTransition {
                from: ModuleState::PowerOn,
                to: ModuleState::SelfTest,
                event: "run_self_tests".to_string(),
                guard: None,
            },
            // Self-test pass -> Crypto Officer mode
            FsmTransition {
                from: ModuleState::SelfTest,
                to: ModuleState::CryptoOfficerMode,
                event: "self_tests_passed".to_string(),
                guard: Some("all_kats_pass".to_string()),
            },
            // Self-test failure -> Error
            FsmTransition {
                from: ModuleState::SelfTest,
                to: ModuleState::ErrorState,
                event: "self_tests_failed".to_string(),
                guard: None,
            },
            // Crypto Officer -> User Mode
            FsmTransition {
                from: ModuleState::CryptoOfficerMode,
                to: ModuleState::UserMode,
                event: "authenticate_user".to_string(),
                guard: Some("valid_credentials".to_string()),
            },
            // User Mode -> Crypto Officer Mode
            FsmTransition {
                from: ModuleState::UserMode,
                to: ModuleState::CryptoOfficerMode,
                event: "authenticate_co".to_string(),
                guard: Some("valid_co_credentials".to_string()),
            },
            // Crypto Officer -> Zeroization
            FsmTransition {
                from: ModuleState::CryptoOfficerMode,
                to: ModuleState::Zeroization,
                event: "zeroize".to_string(),
                guard: None,
            },
            // User Mode -> Zeroization
            FsmTransition {
                from: ModuleState::UserMode,
                to: ModuleState::Zeroization,
                event: "zeroize".to_string(),
                guard: None,
            },
            // Runtime error or detected compromise transitions to ErrorState.
            FsmTransition {
                from: ModuleState::CryptoOfficerMode,
                to: ModuleState::ErrorState,
                event: "runtime_error".to_string(),
                guard: None,
            },
            FsmTransition {
                from: ModuleState::UserMode,
                to: ModuleState::ErrorState,
                event: "runtime_error".to_string(),
                guard: None,
            },
            // Error -> Zeroization
            FsmTransition {
                from: ModuleState::ErrorState,
                to: ModuleState::Zeroization,
                event: "zeroize".to_string(),
                guard: None,
            },
            // Error -> PowerOff (only after the user has acknowledged the
            // error; CSPs are not present in ErrorState because crypto
            // services are disabled).
            FsmTransition {
                from: ModuleState::ErrorState,
                to: ModuleState::PowerOff,
                event: "power_off".to_string(),
                guard: None,
            },
            // Zeroization -> PowerOff (the only path from operational
            // states to shutdown).
            FsmTransition {
                from: ModuleState::Zeroization,
                to: ModuleState::PowerOff,
                event: "zeroization_complete".to_string(),
                guard: None,
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate the FSM against FIPS 140-3 requirements.
///
/// See the module-level docs for the full list of checks. Returns
/// [`CertError::InvalidConfig`] containing one human-readable description
/// per violation.
pub fn validate_fsm(model: &FsmModel) -> CertResult<()> {
    let mut violations = validate_fsm_inner(model);
    violations.sort();
    if violations.is_empty() {
        Ok(())
    } else {
        Err(CertError::InvalidConfig(violations))
    }
}

fn validate_fsm_inner(model: &FsmModel) -> Vec<String> {
    let mut violations = Vec::new();

    // Build adjacency as a fixed-size array indexed by ModuleState as usize.
    let mut adjacency: [Vec<ModuleState>; STATE_COUNT] = std::array::from_fn(|_| Vec::new());
    for t in &model.transitions {
        adjacency[t.from.idx()].push(t.to);
    }

    // Reachability via DFS from the initial state.
    let mut visited = [false; STATE_COUNT];
    let mut stack = vec![model.initial_state];
    visited[model.initial_state.idx()] = true;
    while let Some(state) = stack.pop() {
        for &next in &adjacency[state.idx()] {
            if !visited[next.idx()] {
                visited[next.idx()] = true;
                stack.push(next);
            }
        }
    }
    for state in ModuleState::all() {
        if !visited[state.idx()] {
            violations.push(format!(
                "state {:?} is not reachable from {:?}",
                state, model.initial_state
            ));
        }
    }

    // Dead-state check (PowerOff is allowed to be terminal).
    for state in ModuleState::all() {
        if *state == ModuleState::PowerOff {
            continue;
        }
        if adjacency[state.idx()].is_empty() {
            violations.push(format!(
                "state {:?} is a dead state (no outgoing transitions)",
                state
            ));
        }
    }

    // PowerOn must transition to SelfTest, and ONLY to SelfTest.
    let power_on_targets: Vec<ModuleState> = model
        .transitions
        .iter()
        .filter(|t| t.from == ModuleState::PowerOn)
        .map(|t| t.to)
        .collect();
    if !power_on_targets.contains(&ModuleState::SelfTest) {
        violations.push("PowerOn does not have a mandatory transition to SelfTest".to_string());
    }
    for target in &power_on_targets {
        if *target != ModuleState::SelfTest {
            violations.push(format!(
                "PowerOn has transition to {:?} which bypasses mandatory SelfTest",
                target
            ));
        }
    }

    // ErrorState may only transition to Zeroization or PowerOff.
    for t in &model.transitions {
        if t.from == ModuleState::ErrorState
            && t.to != ModuleState::Zeroization
            && t.to != ModuleState::PowerOff
        {
            violations.push(format!(
                "ErrorState has invalid transition to {:?} (only Zeroization and PowerOff allowed)",
                t.to
            ));
        }
    }

    // Operational states must NOT transition directly to PowerOff — they
    // must zeroize first (FIPS 140-3 §7.9).
    for t in &model.transitions {
        if (t.from == ModuleState::CryptoOfficerMode || t.from == ModuleState::UserMode)
            && t.to == ModuleState::PowerOff
        {
            violations.push(format!(
                "{:?} cannot transition directly to PowerOff — must go through Zeroization first",
                t.from
            ));
        }
    }

    // Duplicate (from, event) detection — ambiguous transitions are a
    // model bug.
    let mut seen: std::collections::HashSet<(ModuleState, &str)> = std::collections::HashSet::new();
    for t in &model.transitions {
        if !seen.insert((t.from, t.event.as_str())) {
            violations.push(format!(
                "duplicate transition for ({:?}, {:?})",
                t.from, t.event
            ));
        }
    }

    violations
}

// ---------------------------------------------------------------------------
// DOT export
// ---------------------------------------------------------------------------

/// Export the FSM as a Graphviz DOT format string.
pub fn export_dot(model: &FsmModel) -> String {
    let mut dot = String::with_capacity(1024);
    dot.push_str("digraph FIPS_FSM {\n");
    dot.push_str("    rankdir=TB;\n");
    dot.push_str("    node [shape=box, style=rounded];\n\n");

    use std::fmt::Write as _;

    for state in ModuleState::all() {
        let shape = match state {
            ModuleState::PowerOff => "doubleoctagon",
            ModuleState::ErrorState => "octagon",
            _ => "box",
        };
        let _ = write!(
            dot,
            "    {} [label=\"{}\", shape={}];\n",
            state.dot_id(),
            state.label(),
            shape
        );
    }
    dot.push('\n');

    for t in &model.transitions {
        let label = if let Some(ref guard) = t.guard {
            format!("{} [{}]", t.event, guard)
        } else {
            t.event.clone()
        };
        let _ = write!(
            dot,
            "    {} -> {} [label=\"{}\"];\n",
            t.from.dot_id(),
            t.to.dot_id(),
            label
        );
    }

    dot.push_str("}\n");
    dot
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_valid(model: &FsmModel) {
        match validate_fsm(model) {
            Ok(()) => {}
            Err(e) => panic!("expected valid FSM, got: {e}"),
        }
    }

    fn violations_of(model: &FsmModel) -> Vec<String> {
        match validate_fsm(model) {
            Ok(()) => Vec::new(),
            Err(CertError::InvalidConfig(v)) => v,
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }
    }

    #[test]
    fn default_model_is_valid() {
        assert_valid(&default_fips_fsm());
    }

    #[test]
    fn all_states_reachable_in_default() {
        assert_valid(&default_fips_fsm());
        assert_eq!(ModuleState::all().len(), 7);
    }

    #[test]
    fn dead_state_detected() {
        let model = FsmModel {
            initial_state: ModuleState::PowerOff,
            transitions: vec![
                FsmTransition {
                    from: ModuleState::PowerOff,
                    to: ModuleState::PowerOn,
                    event: "power_on".to_string(),
                    guard: None,
                },
                FsmTransition {
                    from: ModuleState::PowerOn,
                    to: ModuleState::SelfTest,
                    event: "run_self_tests".to_string(),
                    guard: None,
                },
                // SelfTest is dead.
            ],
        };
        assert!(violations_of(&model)
            .iter()
            .any(|v| v.contains("dead state")));
    }

    #[test]
    fn unreachable_state_detected() {
        let model = FsmModel {
            initial_state: ModuleState::PowerOff,
            transitions: vec![
                FsmTransition {
                    from: ModuleState::PowerOff,
                    to: ModuleState::PowerOn,
                    event: "power_on".to_string(),
                    guard: None,
                },
                FsmTransition {
                    from: ModuleState::PowerOn,
                    to: ModuleState::SelfTest,
                    event: "run_self_tests".to_string(),
                    guard: None,
                },
                FsmTransition {
                    from: ModuleState::SelfTest,
                    to: ModuleState::CryptoOfficerMode,
                    event: "pass".to_string(),
                    guard: None,
                },
                FsmTransition {
                    from: ModuleState::CryptoOfficerMode,
                    to: ModuleState::UserMode,
                    event: "auth".to_string(),
                    guard: None,
                },
                FsmTransition {
                    from: ModuleState::UserMode,
                    to: ModuleState::Zeroization,
                    event: "zeroize".to_string(),
                    guard: None,
                },
                FsmTransition {
                    from: ModuleState::Zeroization,
                    to: ModuleState::PowerOff,
                    event: "done".to_string(),
                    guard: None,
                },
                FsmTransition {
                    from: ModuleState::ErrorState,
                    to: ModuleState::PowerOff,
                    event: "power_off".to_string(),
                    guard: None,
                },
            ],
        };
        assert!(violations_of(&model)
            .iter()
            .any(|v| v.contains("not reachable")));
    }

    #[test]
    fn self_test_bypass_rejected() {
        let mut model = default_fips_fsm();
        model.transitions.push(FsmTransition {
            from: ModuleState::PowerOn,
            to: ModuleState::CryptoOfficerMode,
            event: "skip_tests".to_string(),
            guard: None,
        });
        assert!(violations_of(&model)
            .iter()
            .any(|v| v.contains("bypasses mandatory SelfTest")));
    }

    #[test]
    fn error_state_invalid_exit_rejected() {
        let mut model = default_fips_fsm();
        model.transitions.push(FsmTransition {
            from: ModuleState::ErrorState,
            to: ModuleState::CryptoOfficerMode,
            event: "recover".to_string(),
            guard: None,
        });
        assert!(violations_of(&model)
            .iter()
            .any(|v| v.contains("ErrorState has invalid transition")));
    }

    #[test]
    fn operational_to_poweroff_without_zeroize_rejected() {
        let mut model = default_fips_fsm();
        model.transitions.push(FsmTransition {
            from: ModuleState::CryptoOfficerMode,
            to: ModuleState::PowerOff,
            event: "power_off".to_string(),
            guard: None,
        });
        assert!(violations_of(&model)
            .iter()
            .any(|v| v.contains("must go through Zeroization first")));
    }

    #[test]
    fn duplicate_transition_detected() {
        let mut model = default_fips_fsm();
        model.transitions.push(FsmTransition {
            from: ModuleState::PowerOff,
            to: ModuleState::PowerOn,
            event: "power_on".to_string(), // duplicates the existing one
            guard: None,
        });
        assert!(violations_of(&model)
            .iter()
            .any(|v| v.contains("duplicate transition")));
    }

    #[test]
    fn error_state_to_zeroization_allowed() {
        let model = default_fips_fsm();
        let error_exits: Vec<_> = model
            .transitions
            .iter()
            .filter(|t| t.from == ModuleState::ErrorState)
            .collect();
        assert!(!error_exits.is_empty());
        for t in &error_exits {
            assert!(
                t.to == ModuleState::Zeroization || t.to == ModuleState::PowerOff,
                "unexpected ErrorState exit to {:?}",
                t.to
            );
        }
    }

    #[test]
    fn transition_evaluates_guards() {
        let model = default_fips_fsm();
        // SelfTest -> CryptoOfficerMode is gated on `all_kats_pass`.
        let ok = model
            .transition(ModuleState::SelfTest, "self_tests_passed", |g| {
                g == "all_kats_pass"
            })
            .unwrap();
        assert_eq!(ok, ModuleState::CryptoOfficerMode);

        // Guard returns false -> fail.
        let err = model
            .transition(ModuleState::SelfTest, "self_tests_passed", |_| false)
            .unwrap_err();
        assert!(matches!(err, FsmTransitionError::GuardFailed { .. }));
    }

    #[test]
    fn transition_rejects_unknown_event() {
        let model = default_fips_fsm();
        let err = model
            .transition(ModuleState::PowerOff, "bogus", |_| true)
            .unwrap_err();
        assert!(matches!(err, FsmTransitionError::NoSuchTransition { .. }));
    }

    #[test]
    fn next_state_lookup_works() {
        let model = default_fips_fsm();
        assert_eq!(
            model.next_state(ModuleState::PowerOff, "power_on"),
            Some(ModuleState::PowerOn)
        );
        assert_eq!(
            model.next_state(ModuleState::PowerOn, "run_self_tests"),
            Some(ModuleState::SelfTest)
        );
        assert_eq!(
            model.next_state(ModuleState::Zeroization, "zeroization_complete"),
            Some(ModuleState::PowerOff)
        );
        assert_eq!(model.next_state(ModuleState::PowerOff, "bogus"), None);
    }

    #[test]
    fn dot_export_contains_all_states() {
        let model = default_fips_fsm();
        let dot = export_dot(&model);
        for state in ModuleState::all() {
            assert!(
                dot.contains(state.dot_id()),
                "DOT output missing state: {}",
                state.dot_id()
            );
        }
    }

    #[test]
    fn dot_export_is_valid_digraph() {
        let model = default_fips_fsm();
        let dot = export_dot(&model);
        assert!(dot.starts_with("digraph FIPS_FSM {"));
        assert!(dot.ends_with("}\n"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn dot_export_includes_guards() {
        let model = default_fips_fsm();
        let dot = export_dot(&model);
        assert!(dot.contains("all_kats_pass"));
    }

    #[test]
    fn module_state_serialization_roundtrip() {
        for state in ModuleState::all() {
            let json = serde_json::to_string(state).unwrap();
            let parsed: ModuleState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, parsed);
        }
    }

    #[test]
    fn missing_self_test_transition_detected() {
        let model = FsmModel {
            initial_state: ModuleState::PowerOff,
            transitions: vec![FsmTransition {
                from: ModuleState::PowerOff,
                to: ModuleState::PowerOn,
                event: "power_on".to_string(),
                guard: None,
            }],
        };
        assert!(violations_of(&model)
            .iter()
            .any(|v| v.contains("mandatory transition to SelfTest")));
    }

    #[test]
    fn shutdown_must_zeroize_in_default_model() {
        // Confirm the default model has no direct CO/User -> PowerOff edge.
        let model = default_fips_fsm();
        for t in &model.transitions {
            if t.from == ModuleState::CryptoOfficerMode || t.from == ModuleState::UserMode {
                assert_ne!(
                    t.to,
                    ModuleState::PowerOff,
                    "default model must not allow direct shutdown"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime FSM (audit V2 / V3)
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Lifecycle events the runtime FSM understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Bring the module out of the powered-off state.
    PowerOn,
    /// Begin running the power-on self tests.
    RunSelfTests,
    /// All self-tests passed (guarded by `all_kats_pass`).
    SelfTestsPassed,
    /// One or more self-tests failed.
    SelfTestsFailed,
    /// Force-zeroize CSPs and return to power-off.
    Zeroize,
    /// Power off the module.
    PowerOff,
}

impl Event {
    fn name(self) -> &'static str {
        match self {
            Event::PowerOn => "power_on",
            Event::RunSelfTests => "run_self_tests",
            Event::SelfTestsPassed => "self_tests_passed",
            Event::SelfTestsFailed => "self_tests_failed",
            Event::Zeroize => "zeroize",
            Event::PowerOff => "power_off",
        }
    }
}

/// Reason supplied to a [`ZeroizeHook`] when the module enters `ErrorState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorReason {
    /// One or more known-answer tests failed.
    KatFailure,
    /// The module-binary integrity check did not match.
    IntegrityFailure,
    /// A runtime invariant was violated (e.g. caught panic at FFI boundary).
    FatalRuntimeError,
}

/// Hook invoked exactly once when the module transitions into `ErrorState`.
pub trait ZeroizeHook {
    /// Wipe sensitive state and record the supplied [`ErrorReason`].
    fn zeroize(&mut self, reason: ErrorReason);
}

/// No-op hook used in tests where a real zeroize would prevent post-mortem.
#[derive(Debug, Default)]
pub struct NoopZeroizeHook;

impl ZeroizeHook for NoopZeroizeHook {
    fn zeroize(&mut self, _reason: ErrorReason) {}
}

/// Runtime, atomic-state FSM driven by the model from [`default_fips_fsm`].
pub struct ModuleFsm {
    model: FsmModel,
    state: AtomicU8,
    error_latched: AtomicBool,
    guard: std::sync::RwLock<Option<Box<dyn Fn(&str) -> bool + Send + Sync>>>,
}

/// Convert a [`ModuleState`] to its canonical `u8` discriminant.
///
/// This delegates to the `#[repr(u8)]` discriminant via `as u8`, so the
/// mapping is single-sourced from the enum definition and cannot drift.
#[inline]
fn state_to_u8(s: ModuleState) -> u8 {
    s as u8
}

/// Inverse of [`state_to_u8`].
///
/// Any byte value that does not match a defined discriminant is mapped to
/// [`ModuleState::ErrorState`] (fail-secure: an unrecognised on-disk byte
/// drives the runtime into the error latch, not into one of the
/// operational states).
#[inline]
fn u8_to_state(v: u8) -> ModuleState {
    match v {
        x if x == ModuleState::PowerOff as u8 => ModuleState::PowerOff,
        x if x == ModuleState::PowerOn as u8 => ModuleState::PowerOn,
        x if x == ModuleState::SelfTest as u8 => ModuleState::SelfTest,
        x if x == ModuleState::CryptoOfficerMode as u8 => ModuleState::CryptoOfficerMode,
        x if x == ModuleState::UserMode as u8 => ModuleState::UserMode,
        x if x == ModuleState::Zeroization as u8 => ModuleState::Zeroization,
        x if x == ModuleState::ErrorState as u8 => ModuleState::ErrorState,
        _ => ModuleState::ErrorState,
    }
}

#[cfg(test)]
mod state_u8_mapping_tests {
    use super::*;

    #[test]
    fn state_u8_roundtrip() {
        for s in ModuleState::all() {
            assert_eq!(u8_to_state(state_to_u8(*s)), *s, "roundtrip for {:?}", s);
        }
    }

    #[test]
    fn unknown_byte_maps_to_error_state() {
        assert_eq!(u8_to_state(255), ModuleState::ErrorState);
    }
}

impl ModuleFsm {
    /// Construct a runtime FSM seeded with `model`'s `initial_state`.
    pub fn new(model: FsmModel) -> Self {
        let initial = state_to_u8(model.initial_state);
        Self {
            model,
            state: AtomicU8::new(initial),
            error_latched: AtomicBool::new(false),
            guard: std::sync::RwLock::new(None),
        }
    }

    /// Read the current state. Acquires no locks.
    pub fn current_state(&self) -> ModuleState {
        u8_to_state(self.state.load(Ordering::Acquire))
    }

    /// Install a guard predicate; if unset, every guarded transition fails closed.
    ///
    /// If the underlying `RwLock` is poisoned (because a prior writer
    /// panicked while installing a different guard), this recovers
    /// gracefully via `into_inner()` rather than propagating the panic.
    /// Recovery preserves fail-secure semantics: the next CAS in
    /// `try_transition` re-reads the latched state, so a poisoned-and-
    /// recovered guard slot cannot allow a guarded transition that the
    /// FSM state machine itself would refuse.
    pub fn set_guard<F>(&self, predicate: F)
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        let mut g = match self.guard.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g = Some(Box::new(predicate));
    }

    /// Attempt to transition on `event`.
    pub fn try_transition(&self, event: Event) -> Result<ModuleState, FsmTransitionError> {
        let event_name = event.name();
        loop {
            let current_u8 = self.state.load(Ordering::Acquire);
            let current = u8_to_state(current_u8);
            let edge = self
                .model
                .transitions
                .iter()
                .find(|t| t.from == current && t.event == event_name);
            let edge = match edge {
                Some(t) => t,
                None => {
                    return Err(FsmTransitionError::NoSuchTransition {
                        from: current,
                        event: event_name.to_string(),
                    });
                }
            };
            if let Some(g) = &edge.guard {
                // Recover from a poisoned lock rather than panicking — see
                // `set_guard` for the rationale.
                let guard_g = match self.guard.read() {
                    Ok(g) => g,
                    Err(p) => p.into_inner(),
                };
                let allowed = guard_g.as_ref().map(|f| f(g.as_str())).unwrap_or(false);
                if !allowed {
                    return Err(FsmTransitionError::GuardFailed {
                        guard: g.clone(),
                        from: current,
                        to: edge.to,
                        event: event_name.to_string(),
                    });
                }
            }
            let to_u8 = state_to_u8(edge.to);
            if self
                .state
                .compare_exchange(current_u8, to_u8, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(edge.to);
            }
        }
    }

    /// Transition unconditionally into `ErrorState`; fire `hook.zeroize(reason)` exactly once.
    ///
    /// The state byte is written via a CAS loop rather than a blind
    /// `store` so that a concurrent `try_transition` cannot lose its
    /// race and silently revert the error latch. If the CAS sees that
    /// another writer has already moved the FSM to `ErrorState`, this
    /// returns immediately; otherwise it keeps retrying until it
    /// observes either its own success or another thread's `ErrorState`
    /// write.
    pub fn enter_error_state<H: ZeroizeHook>(
        &self,
        reason: ErrorReason,
        hook: &mut H,
    ) -> Result<(), FsmTransitionError> {
        if self
            .error_latched
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            hook.zeroize(reason);
        }
        let target = state_to_u8(ModuleState::ErrorState);
        loop {
            let current = self.state.load(Ordering::Acquire);
            if current == target {
                return Ok(());
            }
            match self
                .state
                .compare_exchange(current, target, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }
    }
}
