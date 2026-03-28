
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
use rgbstd::contract::{AllocatedState, AssignmentsFilter, BuilderError, TransitionBuilder};
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

pub fn parse_amount(value: &OutrValue) -> Result<Amount, CompositionError> {
    match value {
        OutrValue::Int(v) if *v >= 0 => Ok(Amount::from(*v as u64)),
        _ => Err(CompositionError::Unexpected(
            "validator outstack values must be non-negative integers".to_string(),
        )),
    }
}

pub fn get_interface(consignment: &Consignment<false>) -> Result<serde_json::Value, CompositionError> {
    let interface_transition = consignment.schema.transitions.get(&TransitionType::with(65535u16))
        .ok_or(CompositionError::Unexpected("interface transition not found".to_string()))?;
    let interface_name = interface_transition.name.to_string();
    let interface_libid = LibId::from(base62_to_hash256(&interface_name[9..])?);
    let interface_outr_values =
        run_script(&consignment, interface_libid, 0, Vec::<ScriptParam>::new())
        .map_err(|e| e.to_string())?;
    if interface_outr_values.len() != 1 {
        return Err(CompositionError::Unexpected(
            "interface outr values must provide only one value".to_string(),
        ));
    }
    let interface_str = outr_value_to_str(&interface_outr_values[0])?;
    let interface: serde_json::Value = serde_json::from_str(interface_str)
        .map_err(|e| CompositionError::Unexpected(format!("Failed to parse interface as JSON: {}", e)))?;
    Ok(interface)
}

pub fn add_transition_states(
    abi: &Vec<serde_json::Value>,
    outputs: &Vec<OutrValue>,
    mut main_builder: TransitionBuilder,
    beneficiary_seal: &BuilderSeal<GraphSeal>,
    change_seal: &BuilderSeal<GraphSeal>,
) -> Result<TransitionBuilder, CompositionError> {
    let mut stashed_seal: Option<BuilderSeal<GraphSeal>> = None;
    for (i, value) in abi.iter().enumerate() {
        let outr_value = &outputs[i];
        let abi_name = value.get("name").and_then(|v| v.as_str()).unwrap();
        let abi_type = AssignmentType::from(value.get("type").and_then(|v| v.as_u64()).unwrap() as u16);
        match abi_name {
            "benifery" => {
                let received = parse_amount(outr_value)?;
                if received > Amount::ZERO {
                    main_builder = main_builder.add_fungible_state_raw(
                        abi_type,
                        beneficiary_seal.clone(),
                        received,
                    )?;
                }
            },
            "change" => {
                let change = parse_amount(outr_value)?;
                if change > Amount::ZERO {
                    main_builder = main_builder.add_fungible_state_raw(
                        abi_type,
                        change_seal.clone(),
                        change,
                    )?;
                }
            },
            "owner" => {
                // 解析state的格式为"txid:vout"，其后必须跟一个state值，然后一同添加到main_builder中
                let s = match outr_value {
                    OutrValue::Bytes(v) => std::str::from_utf8(v.as_slice())
                        .map_err(|e| {
                            CompositionError::Unexpected(format!(
                                "state must be utf-8 bytes: {}",
                                e
                            ))
                        })?,
                    _ => {
                        return Err(CompositionError::Unexpected(
                            "state must be bytes encoded as 'txid:vout'"
                                .to_string(),
                        ));
                    }
                };
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() != 2 {
                    return Err(CompositionError::Unexpected(
                        "state must be in the format of txid:vout".to_string(),
                    ));
                }
                let txid = parts[0].parse::<Txid>().map_err(|e| {
                    CompositionError::Unexpected(format!(
                        "invalid txid in state '{}': {}",
                        parts[0], e
                    ))
                })?;
                let vout = parts[1].parse::<u32>().map_err(|e| {
                    CompositionError::Unexpected(format!(
                        "invalid vout in state '{}': {}",
                        parts[1], e
                    ))
                })?;
                let outpoint = Outpoint::new(txid, vout);
                stashed_seal = Some(BuilderSeal::Revealed(GraphSeal::rand_from(outpoint)));
            },
            "amount" => {
                let local_stashed_seal = stashed_seal.ok_or_else(|| {
                    CompositionError::Unexpected(
                        "state 'amount' encountered before 'owner'".to_string(),
                    )
                })?;
                let amount = parse_amount(outr_value)?;
                main_builder = main_builder.add_fungible_state_raw(
                    abi_type,
                    local_stashed_seal,
                    amount,
                )?;
                stashed_seal = None;
        },
            _ => return Err(CompositionError::Unexpected(
                "state must be in the format of txid:vout:amount".to_string(),
            )),
        }
    }
    Ok(main_builder)
}