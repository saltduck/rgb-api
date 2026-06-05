// RGB API library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    add_transition_states_with_terminals, generate_transition_parameters_from_args, get_interface,
    main_assignment_type_from_returns_abi, run_script_with_contract_state,
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

#[derive(Clone, Debug)]
pub struct MultipartyTransitionResult {
    pub meta: PsbtMeta,
    pub witness_id: Txid,
    pub transition_id: OpId,
    pub transfer: Transfer,
    pub terminal_outputs: Vec<OutputSeal>,
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
    if plan.inputs.is_empty() {
        return Err(WalletError::Custom(
            "multiparty transition requires at least one explicit RGB input".to_string(),
        ));
    }

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
        assert_expected_assignments(seal, &list, expected_by_seal.get(&seal))?;
        for (opout, state) in list {
            main_builder = main_builder.add_input(opout, state.clone())?;
            *input_type_counts.entry(opout.ty).or_insert(0) += 1;
            if opout.ty != main_assignment_type {
                let seal = change_seal(opout.ty, &meta).map_err(|e| e.to_string())?;
                main_builder = main_builder.add_owned_state_raw(opout.ty, seal, state)?;
            } else if let AllocatedState::Amount(value) = state {
                sum_inputs += Amount::from(value);
            } else {
                let seal = change_seal(opout.ty, &meta).map_err(|e| e.to_string())?;
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

    let change_seal = change_seal(main_assignment_type, &meta).map_err(|e| e.to_string())?;
    let beneficiary_seal = plan
        .outputs
        .beneficiary_vout
        .map(|vout| BuilderSeal::Revealed(GraphSeal::with_blinded_vout(vout, rand::random())));
    let ben_seal = beneficiary_seal.as_ref().unwrap_or(&change_seal);
    let (mut main_builder, terminal_outputs) = add_transition_states_with_terminals(
        &export,
        abi,
        &outputs,
        main_builder,
        ben_seal,
        &change_seal,
        plan.outputs.beneficiary_vout,
        plan.outputs.change_vout,
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

    Ok(MultipartyTransitionResult {
        meta,
        witness_id,
        transition_id,
        transfer,
        terminal_outputs: transfer_output_seals,
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

fn assert_expected_assignments(
    seal: OutputSeal,
    actual: &HashMap<rgbstd::Opout, AllocatedState>,
    expected: Option<&Vec<(AssignmentType, AllocatedState)>>,
) -> Result<(), WalletError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    for (assignment_type, expected_state) in expected {
        let found = actual
            .iter()
            .any(|(opout, state)| opout.ty == *assignment_type && state == expected_state);
        if !found {
            return Err(WalletError::Custom(format!(
                "specified RGB input {}:{} is missing expected assignment type {}",
                seal.txid,
                seal.vout,
                u16::from(*assignment_type)
            )));
        }
    }
    Ok(())
}

fn change_seal(
    assignment_type: AssignmentType,
    meta: &PsbtMeta,
) -> Result<BuilderSeal<GraphSeal>, CompositionError> {
    let vout = meta
        .change_vout
        .ok_or(CompositionError::NoExtraOrChange(assignment_type))?;
    Ok(BuilderSeal::Revealed(GraphSeal::with_blinded_vout(vout, rand::random())))
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
}
