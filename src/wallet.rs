// RGB API library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{BTreeMap, BTreeSet, HashMap};
#[cfg(feature = "fs")]
use std::path::PathBuf;

#[cfg(all(feature = "fs", feature = "bp"))]
use bpwallet::fs::FsTextStore;
#[cfg(all(feature = "fs", feature = "bp"))]
use bpwallet::Wallet;
#[cfg(all(not(target_arch = "wasm32"), feature = "fs"))]
use nonasync::persistence::PersistenceProvider;
use psrgbt::{RgbOutExt, RgbPropKeyExt, RgbPsbtExt, Terminal};
use rgbstd::containers::{Batch, BuilderSeal, Transfer};
use rgbstd::contract::{AllocatedState, ContractOp};
#[cfg(feature = "fs")]
use rgbstd::persistence::fs::FsBinStore;
use rgbstd::persistence::{
    IndexProvider, MemIndex, MemStash, MemState, StashProvider, StateProvider, Stock, StockError,
};
use rgbstd::rgbcore::dbc::tapret::TapretProof;
use rgbstd::rgbcore::dbc::Proof as _;
use rgbstd::rgbcore::seals::txout::CloseMethod;
use rgbstd::rgbcore::secp256k1::rand;
use rgbstd::validation::{WitnessOrdProvider, WitnessResolverError};
use rgbstd::vm::WitnessOrd;
use rgbstd::{AssignmentType, GraphSeal, Outpoint, OutputSeal, Txid};

#[cfg(all(feature = "fs", feature = "bp"))]
use super::DescriptorRgb;
use super::{
    CompletionError, CompositionError, ContractId, PayError, TransferParams, WalletError,
    WalletProvider,
};
use crate::invoice::RgbInvoice;
use crate::multiparty::{
    build_transition_on_psbt, MultipartyTransitionPlan, MultipartyTransitionResult,
};
use crate::pay::{
    apply_transition_schema_globals_from_contract_state, build_extra_transitions,
    create_change_output_seal, PsbtMeta,
};
use crate::scripts::{
    add_transition_states, generate_transition_parameters_from_args, get_interface,
    main_assignment_type_from_returns_abi, run_script_with_contract_state,
};

struct FasciaResolver {
    witness_id: Txid,
}

impl WitnessOrdProvider for FasciaResolver {
    fn witness_ord(&self, witness_id: Txid) -> Result<WitnessOrd, WitnessResolverError> {
        assert_eq!(witness_id, self.witness_id);
        Ok(WitnessOrd::Tentative)
    }
}

#[derive(Getters)]
pub struct RgbWallet<
    W: WalletProvider,
    S: StashProvider = MemStash,
    H: StateProvider = MemState,
    I: IndexProvider = MemIndex,
> {
    stock: Stock<S, H, I>,
    wallet: W,
}

#[cfg(all(feature = "fs", feature = "bp"))]
impl<
        K,
        D: DescriptorRgb + bpwallet::Descriptor<K>,
        S: StashProvider,
        H: StateProvider,
        I: IndexProvider,
    > RgbWallet<Wallet<K, D>, S, H, I>
{
    #[allow(clippy::result_large_err)]
    pub fn load(
        stock_path: PathBuf,
        wallet_path: PathBuf,
        autosave: bool,
    ) -> Result<Self, WalletError>
    where
        D: serde::Serialize + for<'de> serde::Deserialize<'de>,
        FsBinStore: PersistenceProvider<S>,
        FsBinStore: PersistenceProvider<H>,
        FsBinStore: PersistenceProvider<I>,
    {
        use nonasync::persistence::PersistenceError;
        let provider = FsBinStore::new(stock_path)
            .map_err(|e| WalletError::StockPersist(PersistenceError::with(e)))?;
        let stock = Stock::load(provider, autosave).map_err(WalletError::StockPersist)?;
        let provider = FsTextStore::new(wallet_path)
            .map_err(|e| WalletError::WalletPersist(PersistenceError::with(e)))?;
        let wallet = Wallet::load(provider, autosave).map_err(WalletError::WalletPersist)?;
        Ok(Self { wallet, stock })
    }
}

impl<W: WalletProvider, S: StashProvider, H: StateProvider, I: IndexProvider>
    RgbWallet<W, S, H, I>
{
    pub fn new(stock: Stock<S, H, I>, wallet: W) -> Self { Self { stock, wallet } }

    pub fn stock_mut(&mut self) -> &mut Stock<S, H, I> { &mut self.stock }

    pub fn wallet_mut(&mut self) -> &mut W { &mut self.wallet }

    pub fn history(&self, contract_id: ContractId) -> Result<Vec<ContractOp>, StockError<S, H, I>> {
        let contract = self.stock.contract_data(contract_id)?;
        let wallet = &self.wallet;
        Ok(contract.history(wallet.filter_outpoints(), wallet.filter_witnesses()))
    }

    #[allow(clippy::result_large_err)]
    pub fn pay<P: RgbPropKeyExt, O: RgbOutExt<P>>(
        &mut self,
        invoice: &RgbInvoice,
        params: TransferParams,
    ) -> Result<(W::Psbt, PsbtMeta, Transfer), PayError> {
        self.wallet
            .pay::<S, H, I, P, O>(&mut self.stock, invoice, params)
    }

    #[allow(clippy::result_large_err)]
    pub fn construct_psbt<P: RgbPropKeyExt, O: RgbOutExt<P>>(
        &mut self,
        invoice: &RgbInvoice,
        params: TransferParams,
    ) -> Result<(W::Psbt, PsbtMeta), CompositionError> {
        self.wallet
            .construct_psbt_rgb::<S, H, I, P, O>(&self.stock, invoice, params)
    }

    #[allow(clippy::result_large_err)]
    pub fn transfer(
        &mut self,
        invoice: &RgbInvoice,
        psbt: &mut W::Psbt,
        beneficiary_vout: Option<u32>,
    ) -> Result<Transfer, CompletionError> {
        self.wallet
            .transfer(&mut self.stock, invoice, psbt, beneficiary_vout)
    }

    #[allow(clippy::result_large_err)]
    pub fn transit_with_plan(
        &mut self,
        psbt: &mut W::Psbt,
        plan: &MultipartyTransitionPlan,
    ) -> Result<MultipartyTransitionResult, WalletError> {
        build_transition_on_psbt::<S, H, I, W::P, W::O, W::Psbt>(&mut self.stock, psbt, plan)
    }

    #[allow(clippy::result_large_err)]
    pub fn transit(
        &mut self,
        contract_id: ContractId,
        transition_name: &str,
        args: &[(String, String)],
        beneficiary: Option<&str>,
        params: TransferParams,
    ) -> Result<(W::Psbt, PsbtMeta, Transfer), WalletError> {
        let export = self
            .stock
            .export_contract(contract_id)
            .map_err(|e| e.to_string())?;
        let (interface, interface_libid) = get_interface(&export).map_err(|e| e.to_string())?;

        let (&transition_type, transition_details) = export
            .schema
            .transitions
            .iter()
            .find(|(_, d)| d.name.to_string() == transition_name)
            .ok_or_else(|| {
                WalletError::Custom(format!("transition '{}' not found in schema", transition_name))
            })?;

        let transition_interface = interface.get(transition_name).ok_or_else(|| {
            WalletError::Custom(format!("interface JSON does not contain '{}'", transition_name))
        })?;

        let transition_script = transition_interface.get("script").unwrap();
        let script_pos = transition_script.get("position").unwrap().as_u64().unwrap() as u16;

        let close_method = self.wallet.close_method();

        let (prev_outputs, default_assignment_type) = {
            let filter = self.wallet.filter_unspent();
            let contract = self
                .stock
                .contract_data(contract_id)
                .map_err(|e| e.to_string())?;

            let default_at = *contract
                .schema
                .default_assignment
                .as_ref()
                .unwrap_or(contract.schema.owned_types.keys().next().unwrap());

            let mut prev_outputs = BTreeSet::new();
            for assignment_type in contract.schema.owned_types.keys().copied() {
                for a in contract
                    .fungible_raw(assignment_type, &filter)
                    .map_err(|e| e.to_string())?
                {
                    prev_outputs.insert(a.seal);
                }
                for a in contract
                    .data_raw(assignment_type, &filter)
                    .map_err(|e| e.to_string())?
                {
                    prev_outputs.insert(a.seal);
                }
                for a in contract
                    .rights_raw(assignment_type, &filter)
                    .map_err(|e| e.to_string())?
                {
                    prev_outputs.insert(a.seal);
                }
            }
            (prev_outputs, default_at)
        };

        if prev_outputs.is_empty() {
            return Err(WalletError::Custom(
                "no unspent state found for this contract".to_string(),
            ));
        }

        let prev_outpoints = prev_outputs
            .iter()
            .map(|o| Outpoint::new(o.txid, o.vout.to_u32()));

        let (mut psbt, meta) = if let Some(addr) = beneficiary {
            self.wallet
                .create_psbt_with_address(addr, close_method, prev_outpoints, params)
                .map_err(|e| e.to_string())?
        } else {
            self.wallet
                .create_psbt_no_beneficiary(close_method, prev_outpoints, params)
                .map_err(|e| e.to_string())?
        };

        let beneficiary_seal = meta
            .beneficiary_vout
            .map(|vout| BuilderSeal::Revealed(GraphSeal::with_blinded_vout(vout, rand::random())));

        let abi = transition_interface
            .get("returns")
            .ok_or_else(|| {
                WalletError::Custom("interface transition must contain 'returns'".to_string())
            })?
            .as_array()
            .ok_or_else(|| WalletError::Custom("'returns' must be a JSON array".to_string()))?;
        let main_assignment_type =
            main_assignment_type_from_returns_abi(abi.as_slice(), default_assignment_type)
                .map_err(|e| WalletError::Custom(e.to_string()))?;

        let mut main_builder = self
            .stock
            .transition_builder_raw(contract_id, transition_type)
            .map_err(|e| e.to_string())?;

        let mut sum_inputs = rgbstd::invoice::Amount::ZERO;
        let mut input_type_counts: BTreeMap<AssignmentType, u16> = BTreeMap::new();
        for (_output, list) in self
            .stock
            .contract_assignments_for(contract_id, prev_outputs.iter().copied())
            .map_err(|e| e.to_string())?
        {
            for (opout, state) in list {
                main_builder = main_builder.add_input(opout, state.clone())?;
                *input_type_counts.entry(opout.ty).or_insert(0) += 1;
                if opout.ty != main_assignment_type {
                    let seal =
                        create_change_output_seal(opout.ty, &meta).map_err(|e| e.to_string())?;
                    main_builder = main_builder.add_owned_state_raw(opout.ty, seal, state)?;
                } else if let AllocatedState::Amount(value) = state {
                    sum_inputs += rgbstd::invoice::Amount::from(value);
                } else {
                    let seal =
                        create_change_output_seal(opout.ty, &meta).map_err(|e| e.to_string())?;
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

        let args_map: HashMap<String, String> = args.iter().cloned().collect();

        let parameters = transition_interface.get("parameters").ok_or_else(|| {
            WalletError::Custom("interface transition must contain 'parameters'".to_string())
        })?;
        let script_params = generate_transition_parameters_from_args(
            parameters,
            &args_map,
            sum_inputs,
            &prev_outputs,
        )
        .map_err(|e| e.to_string())?;

        let outputs = {
            let script_contract = self
                .stock
                .contract_data(contract_id)
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

        let change_seal =
            create_change_output_seal(main_assignment_type, &meta).map_err(|e| e.to_string())?;
        let ben_seal = beneficiary_seal.as_ref().unwrap_or(&change_seal);
        main_builder =
            add_transition_states(&export, abi, &outputs, main_builder, ben_seal, &change_seal)
                .map_err(|e| e.to_string())?;

        let transition = {
            let contract = self
                .stock
                .contract_data(contract_id)
                .map_err(|e| e.to_string())?;
            main_builder = apply_transition_schema_globals_from_contract_state(
                main_builder,
                &contract,
                &transition_details.transition_schema,
            )
            .map_err(|e| e.to_string())?;

            main_builder.complete_transition()?
        };

        let extras = build_extra_transitions(&self.stock, contract_id, &prev_outputs, &meta)
            .map_err(|e| e.to_string())?;

        let mut batch = Batch {
            main: transition,
            extras,
        };
        batch.set_priority(u64::MAX);

        psbt.set_rgb_close_method(close_method);
        psbt.set_as_unmodifiable();
        psbt.rgb_embed(batch).map_err(|e| e.to_string())?;

        let fascia = psbt.rgb_commit().map_err(|e| e.to_string())?;
        if matches!(fascia.seal_witness().dbc_proof.method(), CloseMethod::TapretFirst)
            && psbt.rgb_tapret_host_on_change()
        {
            let output = psbt
                .dbc_output::<TapretProof>()
                .ok_or_else(|| WalletError::Custom("no taproot output for tapret".to_string()))?;
            let terminal: Terminal = output
                .terminal_derivation()
                .ok_or_else(|| WalletError::Custom("inconclusive derivation".to_string()))?
                .into();
            let tapret_commitment = output
                .tapret_commitment()
                .map_err(|e| WalletError::Custom(e.to_string()))?;
            self.wallet.add_tapret_tweak(terminal, tapret_commitment)?;
        }

        let witness_id = psbt.get_txid();

        self.stock
            .consume_fascia(fascia, FasciaResolver { witness_id })
            .map_err(|e| e.to_string())?;

        // `Stock::transfer` seeds opids via `opouts_by_outputs` (and secret seal terminals).
        // The mem index does not fill `public_opouts`, so seeds must list every witness
        // output that may own the new transition's state (beneficiary and/or change).
        let mut transfer_output_seals: Vec<OutputSeal> = Vec::new();
        let mut push_seal = |vout: u32| {
            let seal = OutputSeal::new(Outpoint::new(witness_id, vout));
            if !transfer_output_seals.contains(&seal) {
                transfer_output_seals.push(seal);
            }
        };
        if let Some(vout) = meta.beneficiary_vout {
            push_seal(vout);
        }
        if let Some(vout) = meta.change_vout {
            push_seal(vout);
        }
        if transfer_output_seals.is_empty() {
            return Err(WalletError::Custom(
                "cannot build transfer consignment: missing beneficiary_vout and change_vout for witness RGB outputs".into(),
            ));
        }
        let transfer = self
            .stock
            .transfer(contract_id, transfer_output_seals, vec![], [], Some(witness_id))
            .map_err(|e| e.to_string())?;

        Ok((psbt, meta, transfer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn transit_api_is_available_to_wallet_providers<
        W: WalletProvider,
        S: StashProvider,
        H: StateProvider,
        I: IndexProvider,
    >() {
        let _: fn(
            &mut RgbWallet<W, S, H, I>,
            &mut W::Psbt,
            &MultipartyTransitionPlan,
        ) -> Result<MultipartyTransitionResult, WalletError> =
            RgbWallet::<W, S, H, I>::transit_with_plan;

        let _: fn(
            &mut RgbWallet<W, S, H, I>,
            ContractId,
            &str,
            &[(String, String)],
            Option<&str>,
            TransferParams,
        ) -> Result<(W::Psbt, PsbtMeta, Transfer), WalletError> = RgbWallet::<W, S, H, I>::transit;
    }
}
