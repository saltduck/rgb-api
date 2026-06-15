// RGB API library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use psrgbt::{RgbOutExt, RgbPropKeyExt, RgbPsbtExt};
use rgbstd::containers::{Batch, BuilderSeal, Transfer};
use rgbstd::contract::AllocatedState;
use rgbstd::invoice::Amount;
use rgbstd::persistence::{IndexProvider, StashProvider, StateProvider, Stock};
use rgbstd::rgbcore::seals::txout::CloseMethod;
use rgbstd::rgbcore::secp256k1::rand;
use rgbstd::validation::{WitnessOrdProvider, WitnessResolverError};
use rgbstd::vm::WitnessOrd;
use rgbstd::{AssignmentType, ContractId, GraphSeal, OpId, Operation, OutputSeal, Txid};

use crate::pay::{
    apply_transition_schema_globals_from_contract_state, build_extra_transitions, PsbtMeta,
};
use crate::scripts::{
    add_transition_states_with_terminal_vouts, generate_transition_parameters_from_args,
    get_interface, main_assignment_type_from_returns_abi, run_script_with_contract_state,
    TransitionTerminalOutputs,
};
use crate::{CompositionError, WalletError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipartyTransitionInput {
    pub seal: OutputSeal,
    pub expected_assignments: Vec<(AssignmentType, AllocatedState)>,
}

impl MultipartyTransitionInput {
    pub fn new(seal: OutputSeal) -> Self {
        Self {
            seal,
            expected_assignments: vec![],
        }
    }

    pub fn with_expected_assignments(
        seal: OutputSeal,
        expected_assignments: Vec<(AssignmentType, AllocatedState)>,
    ) -> Self {
        Self {
            seal,
            expected_assignments,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipartyOutputPlan {
    pub beneficiary_vout: Option<u32>,
    pub change_vout: Option<u32>,
    pub carrier_vout: u32,
    pub additional_terminal_vouts: BTreeSet<u32>,
}

impl MultipartyOutputPlan {
    pub fn new(beneficiary_vout: Option<u32>, change_vout: Option<u32>, carrier_vout: u32) -> Self {
        Self {
            beneficiary_vout,
            change_vout,
            carrier_vout,
            additional_terminal_vouts: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipartyTransitionPlan {
    pub contract_id: ContractId,
    pub transition_name: String,
    pub args: Vec<(String, String)>,
    pub inputs: Vec<MultipartyTransitionInput>,
    pub close_method: CloseMethod,
    pub outputs: MultipartyOutputPlan,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssignmentTerminalRef {
    pub abi_name: String,
    pub occurrence: usize,
}

impl AssignmentTerminalRef {
    pub fn new(abi_name: impl Into<String>, occurrence: usize) -> Self {
        Self {
            abi_name: abi_name.into(),
            occurrence,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LateBoundArg {
    FinalTxOutpoint { vout: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultipartyAdvancedTransitionPlan {
    pub base: MultipartyTransitionPlan,
    pub input_owners: BTreeMap<OutputSeal, String>,
    pub change_vouts_by_owner: BTreeMap<String, u32>,
    pub terminal_vouts: BTreeMap<String, u32>,
    pub assignment_terminal_map: BTreeMap<AssignmentTerminalRef, String>,
    pub require_distinct_owner_change_vouts: bool,
    pub late_bound_args: BTreeMap<String, LateBoundArg>,
}

impl MultipartyAdvancedTransitionPlan {
    pub fn new(base: MultipartyTransitionPlan) -> Self {
        Self {
            base,
            input_owners: BTreeMap::new(),
            change_vouts_by_owner: BTreeMap::new(),
            terminal_vouts: BTreeMap::new(),
            assignment_terminal_map: BTreeMap::new(),
            require_distinct_owner_change_vouts: false,
            late_bound_args: BTreeMap::new(),
        }
    }

    pub fn with_input_owner(mut self, seal: OutputSeal, owner_id: impl Into<String>) -> Self {
        self.input_owners.insert(seal, owner_id.into());
        self
    }

    pub fn with_owner_change_vout(mut self, owner_id: impl Into<String>, vout: u32) -> Self {
        self.change_vouts_by_owner.insert(owner_id.into(), vout);
        self
    }

    pub fn with_terminal_vout(mut self, terminal_id: impl Into<String>, vout: u32) -> Self {
        self.terminal_vouts.insert(terminal_id.into(), vout);
        self
    }

    pub fn with_assignment_terminal(
        mut self,
        assignment: AssignmentTerminalRef,
        terminal_id: impl Into<String>,
    ) -> Self {
        self.assignment_terminal_map
            .insert(assignment, terminal_id.into());
        self
    }

    pub fn require_distinct_owner_change_vouts(mut self) -> Self {
        self.require_distinct_owner_change_vouts = true;
        self
    }

    pub fn with_late_bound_arg(mut self, name: impl Into<String>, arg: LateBoundArg) -> Self {
        self.late_bound_args.insert(name.into(), arg);
        self
    }
}

#[derive(Clone, Debug)]
pub struct MultipartyTransitionResult {
    pub meta: PsbtMeta,
    pub witness_id: Txid,
    pub commitment_txid: Txid,
    pub transition_id: OpId,
    pub transfer: Transfer,
    pub terminal_outputs: Vec<OutputSeal>,
}

struct MultipartyBuildOutput {
    result: Option<MultipartyTransitionResult>,
    commitment_txid: Txid,
}

#[derive(Default)]
struct MultipartySealCache {
    witness_vout_seals: BTreeMap<u32, BuilderSeal<GraphSeal>>,
}

impl MultipartySealCache {
    fn seal_for_vout(&mut self, vout: u32) -> BuilderSeal<GraphSeal> {
        self.witness_vout_seals
            .entry(vout)
            .or_insert_with(|| BuilderSeal::Revealed(GraphSeal::with_blinded_vout(vout, rand::random())))
            .clone()
    }
}

struct MultipartyFasciaResolver {
    witness_id: Txid,
}

impl WitnessOrdProvider for MultipartyFasciaResolver {
    fn witness_ord(&self, witness_id: Txid) -> Result<WitnessOrd, WitnessResolverError> {
        assert_eq!(witness_id, self.witness_id);
        Ok(WitnessOrd::Tentative)
    }
}

#[allow(clippy::result_large_err)]
pub fn build_transition_on_psbt<
    S: StashProvider,
    H: StateProvider,
    I: IndexProvider,
    P: RgbPropKeyExt,
    O: RgbOutExt<P>,
    Psbt: RgbPsbtExt<P, O>,
>(
    stock: &mut Stock<S, H, I>,
    psbt: &mut Psbt,
    plan: &MultipartyTransitionPlan,
) -> Result<MultipartyTransitionResult, WalletError> {
    let advanced = MultipartyAdvancedTransitionPlan::new(plan.clone());
    build_transition_on_psbt_inner::<S, H, I, P, O, Psbt>(
        stock, psbt, &advanced, None, false, None,
    )?
        .result
        .ok_or_else(|| WalletError::Custom("internal multiparty build returned no result".into()))
}

#[allow(clippy::result_large_err)]
pub fn build_advanced_transition_on_psbt<
    S: StashProvider,
    H: StateProvider,
    I: IndexProvider,
    P: RgbPropKeyExt,
    O: RgbOutExt<P>,
    Psbt: RgbPsbtExt<P, O> + Clone,
>(
    stock: &mut Stock<S, H, I>,
    psbt: &mut Psbt,
    plan: &MultipartyAdvancedTransitionPlan,
) -> Result<MultipartyTransitionResult, WalletError> {
    if plan.late_bound_args.is_empty() {
        return build_transition_on_psbt_inner::<S, H, I, P, O, Psbt>(
            stock, psbt, plan, None, false, None,
        )?
        .result
        .ok_or_else(|| WalletError::Custom("internal multiparty build returned no result".into()));
    }

    let mut seal_cache = MultipartySealCache::default();
    let mut candidate_txid = psbt.get_txid();
    for _ in 0..8 {
        let mut probe_plan = plan.clone();
        probe_plan.base.args =
            resolve_late_bound_args(&plan.base.args, &plan.late_bound_args, candidate_txid)?;
        let mut probe_psbt = psbt.clone();
        let probe_result = build_transition_on_psbt_inner::<S, H, I, P, O, Psbt>(
            stock,
            &mut probe_psbt,
            &probe_plan,
            None,
            true,
            Some(&mut seal_cache),
        )?;
        if probe_result.commitment_txid == candidate_txid {
            let mut final_psbt = psbt.clone();
            let final_result = build_transition_on_psbt_inner::<S, H, I, P, O, Psbt>(
                stock,
                &mut final_psbt,
                &probe_plan,
                Some(candidate_txid),
                false,
                Some(&mut seal_cache),
            )?;
            *psbt = final_psbt;
            return final_result.result.ok_or_else(|| {
                WalletError::Custom("internal multiparty build returned no result".into())
            });
        }
        candidate_txid = probe_result.commitment_txid;
    }
    Err(WalletError::Custom(
        "late-bound transition args did not converge to a stable commitment txid; self-referential final txid arguments are unsupported".into(),
    ))
}

#[allow(clippy::result_large_err)]
fn build_transition_on_psbt_inner<
    S: StashProvider,
    H: StateProvider,
    I: IndexProvider,
    P: RgbPropKeyExt,
    O: RgbOutExt<P>,
    Psbt: RgbPsbtExt<P, O>,
>(
    stock: &mut Stock<S, H, I>,
    psbt: &mut Psbt,
    advanced_plan: &MultipartyAdvancedTransitionPlan,
    expected_commitment_txid: Option<Txid>,
    probe_only: bool,
    mut seal_cache: Option<&mut MultipartySealCache>,
) -> Result<MultipartyBuildOutput, WalletError> {
    let plan = &advanced_plan.base;
    if plan.inputs.is_empty() {
        return Err(WalletError::Custom(
            "multiparty transition requires at least one explicit RGB input".to_string(),
        ));
    }
    validate_multiparty_output_plan(advanced_plan)?;

    let meta = PsbtMeta {
        beneficiary_vout: plan.outputs.beneficiary_vout,
        change_vout: plan.outputs.change_vout,
    };

    let export = stock
        .export_contract(plan.contract_id)
        .map_err(|e| e.to_string())?;
    let (interface, interface_libid) = get_interface(&export).map_err(|e| e.to_string())?;

    let (&transition_type, transition_details) = export
        .schema
        .transitions
        .iter()
        .find(|(_, d)| d.name.to_string() == plan.transition_name)
        .ok_or_else(|| {
            WalletError::Custom(format!(
                "transition '{}' not found in schema",
                plan.transition_name
            ))
        })?;

    let transition_interface = interface.get(&plan.transition_name).ok_or_else(|| {
        WalletError::Custom(format!("interface JSON does not contain '{}'", plan.transition_name))
    })?;
    let transition_script = transition_interface
        .get("script")
        .ok_or_else(|| WalletError::Custom("interface transition must contain 'script'".into()))?;
    let script_pos = transition_script
        .get("position")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            WalletError::Custom("interface script must contain numeric position".into())
        })? as u16;

    let abi = transition_interface
        .get("returns")
        .ok_or_else(|| WalletError::Custom("interface transition must contain 'returns'".into()))?
        .as_array()
        .ok_or_else(|| WalletError::Custom("'returns' must be a JSON array".into()))?;

    let default_assignment_type = {
        let contract = stock
            .contract_data(plan.contract_id)
            .map_err(|e| e.to_string())?;
        *contract
            .schema
            .default_assignment
            .as_ref()
            .unwrap_or(contract.schema.owned_types.keys().next().unwrap())
    };
    let main_assignment_type =
        main_assignment_type_from_returns_abi(abi.as_slice(), default_assignment_type)
            .map_err(|e| WalletError::Custom(e.to_string()))?;

    let prev_outputs = plan
        .inputs
        .iter()
        .map(|input| input.seal)
        .collect::<BTreeSet<_>>();
    if prev_outputs.len() != plan.inputs.len() {
        return Err(WalletError::Custom(
            "multiparty transition inputs must not contain duplicate seals".to_string(),
        ));
    }
    let expected_by_seal = plan
        .inputs
        .iter()
        .map(|input| (input.seal, input.expected_assignments.clone()))
        .collect::<BTreeMap<_, _>>();

    let assignments = stock
        .contract_assignments_for(plan.contract_id, prev_outputs.iter().copied())
        .map_err(|e| e.to_string())?;
    for seal in &prev_outputs {
        if !assignments.contains_key(seal) {
            return Err(WalletError::Custom(format!(
                "specified RGB input {}:{} has no assignment for contract {}",
                seal.txid, seal.vout, plan.contract_id
            )));
        }
    }

    let mut main_builder = stock
        .transition_builder_raw(plan.contract_id, transition_type)
        .map_err(|e| e.to_string())?;
    let mut sum_inputs = Amount::ZERO;
    let mut input_type_counts: BTreeMap<AssignmentType, u16> = BTreeMap::new();

    for (seal, list) in assignments {
        let selected_assignments =
            select_input_assignments(seal, list, expected_by_seal.get(&seal))?;
        let owner_id = advanced_plan.input_owners.get(&seal).map(String::as_str);
        for (opout, state) in selected_assignments {
            main_builder = main_builder.add_input(opout, state.clone())?;
            *input_type_counts.entry(opout.ty).or_insert(0) += 1;
            if opout.ty != main_assignment_type {
                let seal = owner_change_seal(
                    opout.ty,
                    &meta,
                    advanced_plan,
                    owner_id,
                    seal_cache.as_deref_mut(),
                )
                    .map_err(|e| e.to_string())?;
                main_builder = main_builder.add_owned_state_raw(opout.ty, seal, state)?;
            } else if let AllocatedState::Amount(value) = state {
                sum_inputs += Amount::from(value);
            } else {
                let seal = owner_change_seal(
                    opout.ty,
                    &meta,
                    advanced_plan,
                    owner_id,
                    seal_cache.as_deref_mut(),
                )
                    .map_err(|e| e.to_string())?;
                main_builder = main_builder.add_owned_state_raw(opout.ty, seal, state)?;
            }
        }
    }

    for (type_id, occ) in &transition_details.transition_schema.inputs {
        let found = input_type_counts.get(type_id).copied().unwrap_or(0);
        if let Err(mismatch) = occ.check(found) {
            return Err(WalletError::Custom(format!(
                "insufficient transition inputs for type {}: required min={}, max={}, found={}",
                u16::from(*type_id),
                mismatch.min,
                mismatch.max,
                mismatch.found
            )));
        }
    }

    let args_map: HashMap<String, String> = plan.args.iter().cloned().collect();
    let parameters = transition_interface.get("parameters").ok_or_else(|| {
        WalletError::Custom("interface transition must contain 'parameters'".to_string())
    })?;
    let script_params =
        generate_transition_parameters_from_args(parameters, &args_map, sum_inputs, &prev_outputs)
            .map_err(|e| e.to_string())?;

    let outputs = {
        let script_contract = stock
            .contract_data(plan.contract_id)
            .map_err(|e| e.to_string())?;
        run_script_with_contract_state(
            &export,
            interface_libid,
            script_pos,
            script_params,
            script_contract.state,
        )
        .map_err(|e| e.to_string())?
    };

    let change_seal = plan
        .outputs
        .change_vout
        .map(|vout| witness_vout_seal(vout, seal_cache.as_deref_mut()));
    let beneficiary_seal = plan
        .outputs
        .beneficiary_vout
        .map(|vout| witness_vout_seal(vout, seal_cache.as_deref_mut()));
    let ben_seal = beneficiary_seal.as_ref().or(change_seal.as_ref());
    let terminal_seals_by_assignment =
        terminal_seals_by_assignment(advanced_plan, seal_cache.as_deref_mut());
    let (mut main_builder, terminal_outputs) = add_transition_states_with_terminal_vouts(
        &export,
        abi,
        &outputs,
        main_builder,
        ben_seal,
        change_seal.as_ref(),
        plan.outputs.beneficiary_vout,
        plan.outputs.change_vout,
        (!terminal_seals_by_assignment.is_empty()).then_some(&terminal_seals_by_assignment),
    )
    .map_err(|e| e.to_string())?;

    main_builder = {
        let contract = stock
            .contract_data(plan.contract_id)
            .map_err(|e| e.to_string())?;
        apply_transition_schema_globals_from_contract_state(
            main_builder,
            &contract,
            &transition_details.transition_schema,
        )
        .map_err(|e| e.to_string())?
    };
    let transition = main_builder.complete_transition()?;
    let transition_id = transition.id();

    let extras = build_extra_transitions(stock, plan.contract_id, &prev_outputs, &meta)
        .map_err(|e| e.to_string())?;

    let mut batch = Batch {
        main: transition,
        extras,
    };
    batch.set_priority(u64::MAX);

    mark_carrier_output::<P, O, Psbt>(psbt, plan.close_method, plan.outputs.carrier_vout)?;
    psbt.set_rgb_close_method(plan.close_method);
    psbt.set_as_unmodifiable();
    psbt.rgb_embed(batch).map_err(|e| e.to_string())?;

    let fascia = psbt.rgb_commit().map_err(|e| e.to_string())?;
    let witness_id = psbt.get_txid();
    if let Some(expected) = expected_commitment_txid {
        if witness_id != expected {
            return Err(WalletError::Custom(format!(
                "late-bound transition args resolved against txid {}, but final commitment txid is {}",
                expected, witness_id
            )));
        }
    }
    if probe_only {
        return Ok(MultipartyBuildOutput {
            result: None,
            commitment_txid: witness_id,
        });
    }
    stock
        .consume_fascia(fascia, MultipartyFasciaResolver { witness_id })
        .map_err(|e| e.to_string())?;

    let transfer_output_seals =
        terminal_seeds(witness_id, &terminal_outputs, &plan.outputs.additional_terminal_vouts);
    if transfer_output_seals.is_empty() {
        return Err(WalletError::Custom(
            "cannot build transfer consignment: no RGB terminal outputs were produced".into(),
        ));
    }
    let transfer = stock
        .transfer(plan.contract_id, &transfer_output_seals, vec![], [], Some(witness_id))
        .map_err(|e| e.to_string())?;

    Ok(MultipartyBuildOutput {
        commitment_txid: witness_id,
        result: Some(MultipartyTransitionResult {
            meta,
            witness_id,
            commitment_txid: witness_id,
            transition_id,
            transfer,
            terminal_outputs: transfer_output_seals,
        }),
    })
}

fn mark_carrier_output<P: RgbPropKeyExt, O: RgbOutExt<P>, Psbt: RgbPsbtExt<P, O>>(
    psbt: &mut Psbt,
    close_method: CloseMethod,
    carrier_vout: u32,
) -> Result<(), WalletError> {
    let mut found = false;
    for (idx, output) in psbt.outputs_iter_mut().enumerate() {
        let is_target = idx == carrier_vout as usize;
        let already_host = match close_method {
            CloseMethod::OpretFirst => output.is_opret_host(),
            CloseMethod::TapretFirst => output.is_tapret_host(),
        };
        if already_host && !is_target {
            return Err(WalletError::Custom(format!(
                "PSBT already marks a different output as {:?} RGB carrier",
                close_method
            )));
        }
        if is_target {
            found = true;
            match close_method {
                CloseMethod::OpretFirst => {
                    output.set_opret_host();
                }
                CloseMethod::TapretFirst => {
                    output.set_tapret_host();
                }
            }
        }
    }
    if !found {
        return Err(WalletError::Custom(format!(
            "carrier_vout {} is outside PSBT outputs",
            carrier_vout
        )));
    }
    Ok(())
}

fn select_input_assignments(
    seal: OutputSeal,
    actual: HashMap<rgbstd::Opout, AllocatedState>,
    expected: Option<&Vec<(AssignmentType, AllocatedState)>>,
) -> Result<Vec<(rgbstd::Opout, AllocatedState)>, WalletError> {
    let Some(expected) = expected else {
        return Ok(actual.into_iter().collect());
    };
    if expected.is_empty() {
        return Ok(actual.into_iter().collect());
    }

    let mut selected = Vec::with_capacity(expected.len());
    for (assignment_type, expected_state) in expected {
        let matches = actual
            .iter()
            .filter(|(opout, state)| opout.ty == *assignment_type && *state == expected_state)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => {
                return Err(WalletError::Custom(format!(
                    "specified RGB input {}:{} is missing expected assignment type {}",
                    seal.txid,
                    seal.vout,
                    u16::from(*assignment_type)
                )));
            }
            [assignment] => selected.push((*assignment.0, assignment.1.clone())),
            _ => {
                return Err(WalletError::Custom(format!(
                    "specified RGB input {}:{} has multiple matching assignments for type {}",
                    seal.txid,
                    seal.vout,
                    u16::from(*assignment_type)
                )));
            }
        }
    }
    Ok(selected)
}

fn owner_change_seal(
    assignment_type: AssignmentType,
    meta: &PsbtMeta,
    advanced_plan: &MultipartyAdvancedTransitionPlan,
    owner_id: Option<&str>,
    seal_cache: Option<&mut MultipartySealCache>,
) -> Result<BuilderSeal<GraphSeal>, CompositionError> {
    if let Some(owner_id) = owner_id {
        if let Some(vout) = advanced_plan.change_vouts_by_owner.get(owner_id) {
            return Ok(witness_vout_seal(*vout, seal_cache));
        }
        if !advanced_plan.change_vouts_by_owner.is_empty() {
            return Err(CompositionError::Unexpected(format!(
                "missing RGB change vout for owner '{owner_id}'"
            )));
        }
    } else if !advanced_plan.change_vouts_by_owner.is_empty() {
        return Err(CompositionError::Unexpected(
            "multiparty owner change vouts require every RGB input to declare owner_id".into(),
        ));
    }
    if let Some(vout) = meta.change_vout {
        Ok(witness_vout_seal(vout, seal_cache))
    } else {
        Err(CompositionError::NoExtraOrChange(assignment_type))
    }
}

fn witness_vout_seal(
    vout: u32,
    seal_cache: Option<&mut MultipartySealCache>,
) -> BuilderSeal<GraphSeal> {
    match seal_cache {
        Some(cache) => cache.seal_for_vout(vout),
        None => BuilderSeal::Revealed(GraphSeal::with_blinded_vout(vout, rand::random())),
    }
}

fn validate_multiparty_output_plan(
    advanced_plan: &MultipartyAdvancedTransitionPlan,
) -> Result<(), WalletError> {
    let plan = &advanced_plan.base;
    let input_seals = plan
        .inputs
        .iter()
        .map(|input| input.seal)
        .collect::<BTreeSet<_>>();
    for seal in advanced_plan.input_owners.keys() {
        if !input_seals.contains(seal) {
            return Err(WalletError::Custom(format!(
                "input_owners contains unknown RGB input {}:{}",
                seal.txid, seal.vout
            )));
        }
    }
    if !advanced_plan.change_vouts_by_owner.is_empty() {
        let mut owners = HashSet::<&str>::new();
        for input in &plan.inputs {
            let Some(owner_id) = advanced_plan.input_owners.get(&input.seal).map(String::as_str) else {
                return Err(WalletError::Custom(
                    "multiparty owner change vouts require every RGB input to declare owner_id"
                        .into(),
                ));
            };
            owners.insert(owner_id);
            if !advanced_plan.change_vouts_by_owner.contains_key(owner_id) {
                return Err(WalletError::Custom(format!(
                    "missing RGB change vout for owner '{owner_id}'"
                )));
            }
        }
        for owner_id in advanced_plan.change_vouts_by_owner.keys() {
            if !owners.contains(owner_id.as_str()) {
                return Err(WalletError::Custom(format!(
                    "change_vouts_by_owner contains unknown owner '{owner_id}'"
                )));
            }
        }
        if advanced_plan.require_distinct_owner_change_vouts {
            let unique = advanced_plan
                .change_vouts_by_owner
                .values()
                .copied()
                .collect::<BTreeSet<_>>();
            if unique.len() != advanced_plan.change_vouts_by_owner.len() {
                return Err(WalletError::Custom("owner RGB change vouts must be distinct".into()));
            }
        }
    }
    for (assignment, terminal_id) in &advanced_plan.assignment_terminal_map {
        if !advanced_plan.terminal_vouts.contains_key(terminal_id) {
            return Err(WalletError::Custom(format!(
                "assignment terminal {}#{} references unknown terminal '{terminal_id}'",
                assignment.abi_name, assignment.occurrence
            )));
        }
    }
    Ok(())
}

fn terminal_seals_by_assignment(
    advanced_plan: &MultipartyAdvancedTransitionPlan,
    mut seal_cache: Option<&mut MultipartySealCache>,
) -> BTreeMap<(String, usize), (BuilderSeal<GraphSeal>, u32)> {
    advanced_plan
        .assignment_terminal_map
        .iter()
        .filter_map(|(assignment, terminal_id)| {
            advanced_plan
                .terminal_vouts
                .get(terminal_id)
                .map(|vout| {
                    (
                        (assignment.abi_name.clone(), assignment.occurrence),
                        (witness_vout_seal(*vout, seal_cache.as_deref_mut()), *vout),
                    )
                })
        })
        .collect()
}

fn resolve_late_bound_args(
    args: &[(String, String)],
    late_bound_args: &BTreeMap<String, LateBoundArg>,
    txid: Txid,
) -> Result<Vec<(String, String)>, WalletError> {
    if late_bound_args.is_empty() {
        return Ok(args.to_vec());
    }
    let mut resolved = args.to_vec();
    let mut seen = HashSet::<&str>::new();
    for (name, _) in args {
        if late_bound_args.contains_key(name) {
            seen.insert(name.as_str());
        }
    }
    for (name, late) in late_bound_args {
        let value = match late {
            LateBoundArg::FinalTxOutpoint { vout } => format!("{txid}:{vout}"),
        };
        if let Some((_, existing)) = resolved.iter_mut().find(|(arg_name, _)| arg_name == name) {
            *existing = value;
        } else {
            resolved.push((name.clone(), value));
        }
        seen.insert(name.as_str());
    }
    Ok(resolved)
}

fn terminal_seeds(
    witness_id: Txid,
    produced: &TransitionTerminalOutputs,
    additional_witness_vouts: &BTreeSet<u32>,
) -> Vec<OutputSeal> {
    let mut set = BTreeSet::<OutputSeal>::new();
    for vout in &produced.witness_vouts {
        set.insert(OutputSeal::new(rgbstd::Outpoint::new(witness_id, *vout)));
    }
    for vout in additional_witness_vouts {
        set.insert(OutputSeal::new(rgbstd::Outpoint::new(witness_id, *vout)));
    }
    for outpoint in &produced.explicit_outpoints {
        set.insert(OutputSeal::new(*outpoint));
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use psrgbt::{DbcPsbtProof, MpcPsbtError};
    use rgbstd::rgbcore::commit_verify::mpc::ProtocolId;
    use rgbstd::rgbcore::seals::txout::CloseMethod;
    use rgbstd::{Opout, TransitionBundle};

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct Key;

    impl RgbPropKeyExt for Key {
        fn mpc_message(_protocol_id: ProtocolId) -> Self {
            Key
        }
        fn mpc_entropy() -> Self {
            Key
        }
        fn mpc_min_tree_depth() -> Self {
            Key
        }
        fn mpc_commitment() -> Self {
            Key
        }
        fn mpc_proof() -> Self {
            Key
        }
        fn opret_host() -> Self {
            Key
        }
        fn tapret_host() -> Self {
            Key
        }
        fn opret_commitment() -> Self {
            Key
        }
        fn tapret_commitment() -> Self {
            Key
        }
        fn tapret_proof() -> Self {
            Key
        }
        fn rgb_transition(_opid: OpId) -> Self {
            Key
        }
        fn rgb_close_method() -> Self {
            Key
        }
        fn rgb_consumed_by(_contract_id: ContractId) -> Self {
            Key
        }
        fn rgb_tapret_host_on_change() -> Self {
            Key
        }
    }

    #[derive(Clone, Default)]
    struct MockOutput {
        opret_host: bool,
        tapret_host: bool,
    }

    impl RgbOutExt<Key> for MockOutput {
        fn is_opret_host(&self) -> bool {
            self.opret_host
        }

        fn is_tapret_host(&self) -> bool {
            self.tapret_host
        }

        fn set_opret_host(&mut self) -> bool {
            let was_set = self.opret_host;
            self.opret_host = true;
            was_set
        }

        fn set_tapret_host(&mut self) -> bool {
            let was_set = self.tapret_host;
            self.tapret_host = true;
            was_set
        }

        fn get_internal_pk(&self) -> Option<rgbstd::bitcoin::key::UntweakedPublicKey> {
            unimplemented!()
        }

        fn is_tap_tree_empty(&self) -> bool {
            unimplemented!()
        }

        fn set_tap_tree(&mut self, _script_commitment: &rgbstd::bitcoin::ScriptBuf) {
            unimplemented!()
        }

        fn bip32_derivation_terminals(&self) -> Vec<psrgbt::Terminal> {
            unimplemented!()
        }

        fn tap_bip32_derivation_terminals(&self) -> Vec<psrgbt::Terminal> {
            unimplemented!()
        }

        fn proprietary_mpc_messages<'a>(
            &'a self,
        ) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
            std::iter::empty()
        }

        fn proprietary_insert(&mut self, _key: Key, _value: Vec<u8>) {
            unimplemented!()
        }

        fn proprietary_contains_key(&self, _key: &Key) -> bool {
            false
        }

        fn proprietary_get_value(&self, _key: &Key) -> Option<&[u8]> {
            None
        }

        fn proprietary_remove(&mut self, _key: &Key) {
            unimplemented!()
        }
    }

    struct MockPsbt {
        outputs: Vec<MockOutput>,
    }

    impl RgbPsbtExt<Key, MockOutput> for MockPsbt {
        fn get_txid(&self) -> Txid {
            unimplemented!()
        }

        fn modifiable_outputs(&self) -> bool {
            unimplemented!()
        }

        fn set_as_unmodifiable(&mut self) {
            unimplemented!()
        }

        fn unsigned_tx(&self) -> rgbstd::bitcoin::Transaction {
            unimplemented!()
        }

        fn set_opret_host(&mut self) -> bool {
            unimplemented!()
        }

        fn dbc_output<D: DbcPsbtProof>(&self) -> Option<&MockOutput> {
            unimplemented!()
        }

        fn dbc_output_mut<D: DbcPsbtProof>(&mut self) -> Option<(usize, &mut MockOutput)> {
            unimplemented!()
        }

        fn set_opret_commitment(&mut self, _idx: usize) {
            unimplemented!()
        }

        fn set_tapret_commitment(&mut self, _idx: usize) {
            unimplemented!()
        }

        fn proprietary_rgb_contract_consumer_keys<'a>(
            &'a self,
        ) -> impl Iterator<Item = &'a [u8]> + 'a {
            std::iter::empty()
        }

        fn outputs_iter_mut<'a>(&'a mut self) -> impl Iterator<Item = &'a mut MockOutput>
        where
            MockOutput: 'a,
        {
            self.outputs.iter_mut()
        }

        fn proprietary_insert(&mut self, _key: Key, _value: Vec<u8>) {
            unimplemented!()
        }

        fn proprietary_push(&mut self, _key: Key, _value: Vec<u8>) -> Result<(), MpcPsbtError> {
            unimplemented!()
        }

        fn proprietary_contains_key(&self, _key: &Key) -> bool {
            false
        }

        fn proprietary_get_value(&self, _key: &Key) -> Option<&[u8]> {
            None
        }

        fn rgb_bundles(
            &self,
        ) -> Result<BTreeMap<ContractId, TransitionBundle>, psrgbt::RgbPsbtError> {
            unimplemented!()
        }

        fn set_rgb_contract_consumer(
            &mut self,
            _contract_id: ContractId,
            _opout: Opout,
            _opid: OpId,
        ) -> Result<bool, psrgbt::RgbPsbtError> {
            unimplemented!()
        }
    }

    #[test]
    fn carrier_vout_must_exist() {
        let mut psbt = MockPsbt {
            outputs: vec![MockOutput::default()],
        };

        let err =
            mark_carrier_output::<Key, MockOutput, MockPsbt>(&mut psbt, CloseMethod::OpretFirst, 1)
                .unwrap_err();

        assert!(err.to_string().contains("carrier_vout 1"));
        assert!(!psbt.outputs[0].opret_host);
    }

    #[test]
    fn carrier_vout_marks_only_requested_output() {
        let mut psbt = MockPsbt {
            outputs: vec![MockOutput::default(), MockOutput::default()],
        };

        mark_carrier_output::<Key, MockOutput, MockPsbt>(&mut psbt, CloseMethod::TapretFirst, 1)
            .unwrap();

        assert!(!psbt.outputs[0].tapret_host);
        assert!(psbt.outputs[1].tapret_host);
    }

    #[test]
    fn carrier_vout_rejects_different_preexisting_host() {
        let mut psbt = MockPsbt {
            outputs: vec![
                MockOutput {
                    opret_host: true,
                    tapret_host: false,
                },
                MockOutput::default(),
            ],
        };

        let err =
            mark_carrier_output::<Key, MockOutput, MockPsbt>(&mut psbt, CloseMethod::OpretFirst, 1)
                .unwrap_err();

        assert!(err.to_string().contains("different output"));
        assert!(!psbt.outputs[1].opret_host);
    }

    #[test]
    fn legacy_single_change_output_plan_defaults_remain_compatible() {
        let plan = MultipartyOutputPlan::new(Some(0), Some(1), 2);

        assert_eq!(plan.beneficiary_vout, Some(0));
        assert_eq!(plan.change_vout, Some(1));
        assert_eq!(plan.carrier_vout, 2);
    }

    #[test]
    fn legacy_public_struct_literals_remain_source_compatible() {
        let input = MultipartyTransitionInput {
            seal: OutputSeal::new(rgbstd::Outpoint::new(dummy_txid(1), 0)),
            expected_assignments: vec![],
        };
        let outputs = MultipartyOutputPlan {
            beneficiary_vout: Some(0),
            change_vout: Some(1),
            carrier_vout: 2,
            additional_terminal_vouts: BTreeSet::new(),
        };

        assert_eq!(input.expected_assignments.len(), 0);
        assert_eq!(outputs.change_vout, Some(1));
    }

    #[test]
    fn empty_expected_assignments_select_all_input_assignments() {
        let seal = OutputSeal::new(rgbstd::Outpoint::new(dummy_txid(1), 0));
        let state_a = AllocatedState::Amount(100u64.into());
        let state_b = AllocatedState::Amount(200u64.into());
        let opout_a = dummy_opout(1, 0);
        let opout_b = dummy_opout(2, 1);
        let actual = HashMap::from([(opout_a, state_a.clone()), (opout_b, state_b.clone())]);

        let selected = select_input_assignments(seal, actual, Some(&vec![])).unwrap();

        assert_eq!(selected.len(), 2);
        assert!(selected.contains(&(opout_a, state_a)));
        assert!(selected.contains(&(opout_b, state_b)));
    }

    #[test]
    fn expected_assignments_select_only_matching_input_assignments() {
        let seal = OutputSeal::new(rgbstd::Outpoint::new(dummy_txid(1), 0));
        let selected_state = AllocatedState::Amount(100u64.into());
        let unselected_state = AllocatedState::Amount(200u64.into());
        let selected_type = AssignmentType::from(1u16);
        let unselected_type = AssignmentType::from(2u16);
        let selected_opout = dummy_opout(1, 0);
        let unselected_opout = dummy_opout(2, 1);
        let actual = HashMap::from([
            (selected_opout, selected_state.clone()),
            (unselected_opout, unselected_state),
        ]);
        let expected = vec![(selected_type, selected_state.clone())];

        let selected = select_input_assignments(seal, actual, Some(&expected)).unwrap();

        assert_eq!(selected, vec![(selected_opout, selected_state)]);
        assert_eq!(unselected_opout.ty, unselected_type);
    }

    #[test]
    fn expected_assignments_missing_match_fails_closed() {
        let seal = OutputSeal::new(rgbstd::Outpoint::new(dummy_txid(1), 0));
        let actual = HashMap::from([(dummy_opout(1, 0), AllocatedState::Amount(100u64.into()))]);
        let expected = vec![(AssignmentType::from(1u16), AllocatedState::Amount(200u64.into()))];

        let err = select_input_assignments(seal, actual, Some(&expected)).unwrap_err();

        assert!(err.to_string().contains("missing expected assignment"));
    }

    #[test]
    fn expected_assignments_ambiguous_match_fails_closed() {
        let seal = OutputSeal::new(rgbstd::Outpoint::new(dummy_txid(1), 0));
        let state = AllocatedState::Amount(100u64.into());
        let actual =
            HashMap::from([(dummy_opout(1, 0), state.clone()), (dummy_opout(1, 1), state.clone())]);
        let expected = vec![(AssignmentType::from(1u16), state)];

        let err = select_input_assignments(seal, actual, Some(&expected)).unwrap_err();

        assert!(err.to_string().contains("multiple matching assignments"));
    }

    #[test]
    fn owner_change_vouts_must_have_owner_mapping_for_each_input() {
        let input = dummy_input(0);
        let plan = dummy_plan(MultipartyOutputPlan::new(Some(0), Some(1), 3), vec![input.clone(), dummy_input(1)]);
        let advanced = MultipartyAdvancedTransitionPlan::new(plan)
            .with_input_owner(input.seal, "alice")
            .with_owner_change_vout("alice", 1);

        let err = validate_multiparty_output_plan(&advanced).unwrap_err();

        assert!(err
            .to_string()
            .contains("every RGB input to declare owner_id"));
    }

    #[test]
    fn owner_change_vouts_can_require_distinct_seals() {
        let alice = dummy_input(0);
        let bob = dummy_input(1);
        let plan = dummy_plan(MultipartyOutputPlan::new(Some(0), None, 4), vec![alice.clone(), bob.clone()]);
        let advanced = MultipartyAdvancedTransitionPlan::new(plan)
            .with_input_owner(alice.seal, "alice")
            .with_input_owner(bob.seal, "bob")
            .with_owner_change_vout("alice", 1)
            .with_owner_change_vout("bob", 1)
            .require_distinct_owner_change_vouts();

        let err = validate_multiparty_output_plan(&advanced).unwrap_err();

        assert!(err.to_string().contains("must be distinct"));
    }

    #[test]
    fn same_name_change_returns_can_map_to_distinct_terminals() {
        let plan = dummy_plan(MultipartyOutputPlan::new(Some(0), Some(1), 4), vec![dummy_input(0)]);
        let advanced = MultipartyAdvancedTransitionPlan::new(plan)
            .with_terminal_vout("alice_change", 1)
            .with_terminal_vout("bob_change", 2)
            .with_assignment_terminal(AssignmentTerminalRef::new("change", 0), "alice_change")
            .with_assignment_terminal(AssignmentTerminalRef::new("change", 1), "bob_change");

        let map = terminal_seals_by_assignment(&advanced, None);

        assert_eq!(map.get(&("change".to_string(), 0)).map(|(_, vout)| *vout), Some(1));
        assert_eq!(map.get(&("change".to_string(), 1)).map(|(_, vout)| *vout), Some(2));
    }

    #[test]
    fn terminal_mapping_must_reference_known_terminal() {
        let plan = dummy_plan(MultipartyOutputPlan::new(Some(0), Some(1), 4), vec![dummy_input(0)]);
        let advanced = MultipartyAdvancedTransitionPlan::new(plan)
            .with_assignment_terminal(AssignmentTerminalRef::new("change", 0), "missing");

        let err = validate_multiparty_output_plan(&advanced).unwrap_err();

        assert!(err.to_string().contains("unknown terminal"));
    }

    #[test]
    fn late_bound_final_tx_outpoint_overrides_arg_with_commitment_txid() {
        let txid = dummy_txid(9);
        let args = vec![("settler".to_string(), "placeholder".to_string())];
        let late =
            BTreeMap::from([("settler".to_string(), LateBoundArg::FinalTxOutpoint { vout: 7 })]);

        let resolved = resolve_late_bound_args(&args, &late, txid).unwrap();

        assert_eq!(resolved, vec![("settler".to_string(), format!("{txid}:7"))]);
    }

    fn dummy_plan(
        outputs: MultipartyOutputPlan,
        inputs: Vec<MultipartyTransitionInput>,
    ) -> MultipartyTransitionPlan {
        MultipartyTransitionPlan {
            contract_id: ContractId::copy_from_slice(&[1u8; 32]).unwrap(),
            transition_name: "demo".to_string(),
            args: vec![],
            inputs,
            close_method: CloseMethod::OpretFirst,
            outputs,
        }
    }

    fn dummy_input(vout: u32) -> MultipartyTransitionInput {
        MultipartyTransitionInput::new(OutputSeal::new(rgbstd::Outpoint::new(dummy_txid(1), vout)))
    }

    fn dummy_opout(assignment_type: u16, no: u16) -> Opout {
        Opout::new(
            OpId::copy_from_slice([assignment_type as u8; 32]).unwrap(),
            AssignmentType::from(assignment_type),
            no,
        )
    }

    fn dummy_txid(byte: u8) -> Txid {
        format!("{byte:02x}").repeat(32).parse().unwrap()
    }
}
