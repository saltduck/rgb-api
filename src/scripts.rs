
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]



use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::Infallible;

use aluvm::library::{LibId, LibSite};
use aluvm::reg::{Reg32, Reg16, Reg8};
// use aluvm::reg::CoreRegs;
use amplify::confinement::{Confined, U24};
use amplify::num::u5;
use chrono::Utc;
use psrgbt::{RgbOutExt, RgbPropKeyExt, RgbPsbtExt, TapretKeyError, Terminal};
use rgbstd::bitcoin::hashes::sha256d;
use rgbstd::containers::{Batch, BuilderSeal, Transfer};
use rgbstd::contract::{AllocatedState, AssignmentsFilter, BuilderError};
use rgbstd::invoice::{Amount, Beneficiary, InvoiceState, RgbInvoice};
use rgbstd::persistence::{IndexProvider, StashInconsistency, StashProvider, StateProvider, Stock};
use rgbstd::rgbcore::dbc::tapret::{TapretCommitment, TapretProof};
use rgbstd::rgbcore::dbc::Proof;
use rgbstd::rgbcore::seals::txout::{CloseMethod, ExplicitSeal};
use rgbstd::rgbcore::secp256k1::rand;
use rgbstd::validation::WitnessOrdProvider;
use rgbstd::containers::Consignment;
use rgbstd::{
    AssignmentType, ContractId, GraphSeal, Opout, Outpoint, OutputSeal, RevealedData, RevealedState, Transition, TransitionType, Txid
};
use {
    aluvm::Vm,
    aluvm::isa::{Instr, OutrValue},
};
// use rgbstd::vm::{OrdOpRef};
// use rgbstd::vm::contract::{VmContext, OpInfo};
use rgbstd::Vout; // 或你本地的 vout 类型

use crate::filters::{Filter, WalletFilter};
use crate::invoice::NonFungible;
use crate::validation::WitnessResolverError;
use crate::vm::WitnessOrd;
use crate::{CompletionError, CompositionError, PayError, WalletError};

#[derive(Debug, Clone)]
pub(crate) struct ScriptParam {
    pub reg_name: String,
    pub idx: u8,
    pub value: String,
}

pub fn run_script(consignment: &Consignment<false>, lib_id: LibId, pos: u16, params: Vec<ScriptParam>) -> Result<Vec<OutrValue>, CompositionError> {
    let mut vm = Vm::<Instr>::new();
    vm.registers.set_outstack_limit(1024);
    for param in params {
        match param.reg_name.as_str() {
            "a64" => {
                let _ = vm.registers.set_a64(
                    Reg32::from(u5::try_from(param.idx).unwrap()),
                    param.value.parse::<u64>().unwrap(),
                );
            }
            _ => {
                return Err(CompositionError::Unexpected(
                    format!("Invalid register name: {}", param.reg_name),
                ));
            }
        }
    }
    let scripts: BTreeMap<_, _> = 
        consignment.scripts.clone().into_iter().map(|s| (s.id(), s.clone()))
        .collect();
    let ok = vm.exec(LibSite::with(pos, lib_id), |id| scripts.get(&id), &());
    if !ok {
        return Err(CompositionError::Unexpected(
            format!("script {}@{} failed to execute", pos, lib_id),
        ));
    }
    let outputs = vm.registers.outstack().to_vec();
    println!("outputs: {:?}", outputs);
    Ok(outputs)
}

pub fn outr_value_to_str(outr_value: &OutrValue) -> Result<&str, CompositionError> {
    let s = match &outr_value {
        OutrValue::Bytes(v) => {
            match std::str::from_utf8(v.as_slice()) {
                Ok(json_str) => json_str,
                Err(_) => return Err(CompositionError::Unexpected(
                    "outputs[0] is not valid UTF-8 string".to_string(),
                )),
            }
        },
        _ => {
            return Err(CompositionError::Unexpected(
                "outputs[0] must be a bytes value containing JSON string".to_string(),
            ))
        }
    };
    Ok(s)
}

use num_bigint::BigUint;
use num_traits::Zero;

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub fn base62_to_hash256(s: &str) -> Result<[u8; 32], String> {
    if s.is_empty() {
        return Err("empty base62 string".to_string());
    }

    // 与编码函数保持一致：特殊值 "0" 对应全零 hash
    if s == "0" {
        return Ok([0u8; 32]);
    }

    let base = BigUint::from(62u32);
    let mut n = BigUint::zero();

    for ch in s.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|&c| c == ch)
            .ok_or_else(|| format!("invalid base62 character: {}", ch as char))?;

        n = n * &base + BigUint::from(digit as u32);
    }

    let bytes = n.to_bytes_be();
    if bytes.len() > 32 {
        return Err("decoded value does not fit into 32 bytes".to_string());
    }

    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

/// `inputs` 为 interface JSON 里的 `inputs` 数组；`sum_inputs` / `amt` 为本次支付侧已知金额。
pub fn generate_transition_parameters(
    parameters: &serde_json::Value,
    sum_inputs: Amount,
    amt: Amount,
) -> Result<Vec<ScriptParam>, CompositionError> {
    let Some(rows) = parameters.as_array() else {
        return Err(CompositionError::Unexpected(
            "interface parameters must be a JSON array".to_string(),
        ));
    };
    let mut script_params = Vec::new();
    let OS_ASSET: u64 = 4000;
    for input in rows {
        let param_type = input
            .get("type")
            .and_then(|v| v.as_u64());
        let param_name = input.get("name").and_then(|v| v.as_str()).unwrap_or_default();
        match param_name {
            "inputs" | "sum_inputs" if param_type == Some(OS_ASSET) => {
                script_params.push(ScriptParam {
                    reg_name: "a64".to_string(),
                    idx: 0,
                    value: u64::from(sum_inputs).to_string(),
                });
            }
            "amount" | "amt" if param_type == Some(OS_ASSET) => {
                script_params.push(ScriptParam {
                    reg_name: "a64".to_string(),
                    idx: 1,
                    value: u64::from(amt).to_string(),
                });
            }
            _ => {
                return Err(CompositionError::Unexpected(format!(
                    "Invalid parameter name: {} for type: {}",
                    param_name,
                    param_type.unwrap_or_default(),
                )));
            }
        }
    }

    Ok(script_params)
}