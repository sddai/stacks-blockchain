use std::collections::HashMap;
use super::{ClarityCostFunctionReference, SimpleCostSpecification, TypeCheckCost};
use super::CostFunctions::{Linear, Constant, NLogN, LogN};
use vm::types::{Value, QualifiedContractIdentifier, StandardPrincipalData};
use vm::contexts::{OwnedEnvironment, Environment};
use vm::database::MemoryBackingStore;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::boot::boot_code_id;

define_named_enum!(ClarityCostFunctions {
    AnalysisTypeAnnotate("cost_analysis_type_annotate"),
    AnalysisTypeCheck("cost_analysis_type_check"),
    AnalysisTypeLookup("cost_analysis_type_lookup"),
    AnalysisVisit("cost_analysis_visit"),
    AnalysisIterableFunc("cost_analysis_iterable_func"),
    AnalysisOptionCons("cost_analysis_option_cons"),
    AnalysisOptionCheck("cost_analysis_option_check"),
    AnalysisBindName("cost_analysis_bind_name"),
    AnalysisListItemsCheck("cost_analysis_list_items_check"),
    AnalysisCheckTupleGet("cost_analysis_check_tuple_get"),
    AnalysisCheckTupleCons("cost_analysis_check_tuple_cons"),
    AnalysisTupleItemsCheck("cost_analysis_tuple_items_check"),
    AnalysisCheckLet("cost_analysis_check_let"),
    AnalysisLookupFunction("cost_analysis_lookup_function"),
    AnalysisLookupFunctionTypes("cost_analysis_lookup_function_types"),
    AnalysisLookupVariableConst("cost_analysis_lookup_variable_const"),
    AnalysisLookupVariableDepth("cost_analysis_lookup_variable_depth"),
    AstParse("cost_ast_parse"),
    AstCycleDetection("cost_ast_cycle_detection"),
    AnalysisStorage("cost_analysis_storage"),
    AnalysisUseTraitEntry("cost_analysis_use_trait_entry"),
    AnalysisGetFunctionEntry("cost_analysis_get_function_entry"),
    AnalysisFetchContractEntry("cost_analysis_fetch_contract_entry"),
    LookupVariableDepth("cost_lookup_variable_depth"),
    LookupVariableSize("cost_lookup_variable_size"),
    LookupFunction("cost_lookup_function"),
    BindName("cost_bind_name"),
    InnerTypeCheckCost("cost_inner_type_check_cost"),
    UserFunctionApplication("cost_user_function_application"),
    Let("cost_let"),
    If("cost_if"),
    Asserts("cost_asserts"),
    Map("cost_map"),
    Filter("cost_filter"),
    Len("cost_len"),
    Fold("cost_fold"),
    ListCons("cost_list_cons"),
    TypeParseStep("cost_type_parse_step"),
    DataHashCost("cost_data_hash_cost"),
    TupleGet("cost_tuple_get"),
    TupleCons("cost_tuple_cons"),
    Add("cost_add"),
    Sub("cost_sub"),
    Mul("cost_mul"),
    Div("cost_div"),
    Geq("cost_geq"),
    Leq("cost_leq"),
    Le("cost_le"),
    Ge("cost_ge"),
    IntCast("cost_int_cast"),
    Mod("cost_mod"),
    Pow("cost_pow"),
    Sqrti("cost_sqrti"),
    Xor("cost_xor"),
    Not("cost_not"),
    Eq("cost_eq"),
    Begin("cost_begin"),
    Hash160("cost_hash160"),
    Sha256("cost_sha256"),
    Sha512("cost_sha512"),
    Sha512t256("cost_sha512t256"),
    Keccak256("cost_keccak256"),
    Secp256k1recover("cost_secp256k1recover"),
    Secp256k1verify("cost_secp256k1verify"),
    Print("cost_print"),
    SomeCons("cost_some_cons"),
    OkCons("cost_ok_cons"),
    ErrCons("cost_err_cons"),
    DefaultTo("cost_default_to"),
    UnwrapRet("cost_unwrap_ret"),
    UnwrapErrOrRet("cost_unwrap_err_or_ret"),
    IsOkay("cost_is_okay"),
    IsNone("cost_is_none"),
    IsErr("cost_is_err"),
    IsSome("cost_is_some"),
    Unwrap("cost_unwrap"),
    UnwrapErr("cost_unwrap_err"),
    TryRet("cost_try_ret"),
    Match("cost_match"),
    Or("cost_or"),
    And("cost_and"),
    Append("cost_append"),
    Concat("cost_concat"),
    AsMaxLen("cost_as_max_len"),
    ContractCall("cost_contract_call"),
    ContractOf("cost_contract_of"),
    PrincipalOf("cost_principal_of"),
    AtBlock("cost_at_block"),
    LoadContract("cost_load_contract"),
    CreateMap("cost_create_map"),
    CreateVar("cost_create_var"),
    CreateNft("cost_create_nft"),
    CreateFt("cost_create_ft"),
    FetchEntry("cost_fetch_entry"),
    SetEntry("cost_set_entry"),
    FetchVar("cost_fetch_var"),
    SetVar("cost_set_var"),
    ContractStorage("cost_contract_storage"),
    BlockInfo("cost_block_info"),
    StxBalance("cost_stx_balance"),
    StxTransfer("cost_stx_transfer"),
    FtMint("cost_ft_mint"),
    FtTransfer("cost_ft_transfer"),
    FtBalance("cost_ft_balance"),
    NftMint("cost_nft_mint"),
    NftTransfer("cost_nft_transfer"),
    NftOwner("cost_nft_owner"),
});

lazy_static! {
    pub static ref COSTS: HashMap<&'static ClarityCostFunctions, ClarityCostFunctionReference> = {
        let mut m = HashMap::new();
        for f in ClarityCostFunctions::ALL.iter() {
            m.insert(f, ClarityCostFunctionReference::new(boot_code_id("costs"), f.get_name()));
        }
        m
    };
}

pub fn eval_contract_cost(
    env: &mut Environment,
    cost_function: ClarityCostFunctionReference,
    input_size: Option<u64>) -> Result<Value, &'static str> {

    let eval_result = match input_size {
        Some(size) => {
            env.eval_read_only(
                &cost_function.contract_id,
                format!("({} u{})", cost_function.function_name, size).as_str())
        }
        None => {
            env.eval_read_only(
                &cost_function.contract_id,
                format!("({})", cost_function.function_name).as_str())
        }
    };

    match eval_result {
        Ok(Value::Tuple(data)) => {
            match data.data_map.get("runtime") {
                Some(runtime) => Ok(runtime.clone()),
                None => Err("err")
            }
        }, 
        Ok(_) => Err("cost function result not a Tuple"),
        Err(_) => Err("error evaluating result of cost function"),
    }
}

#[test]
fn test_eval_contract_cost() {
    // setup env
    let mut marf = MemoryBackingStore::new();
    let mut owned_env = OwnedEnvironment::new(marf.as_clarity_db());

    // deploy boot cost contract
    owned_env.initialize_contract(boot_code_id("costs"), std::include_str!("../../chainstate/stacks/boot/costs.clar")).unwrap();
    let mut env = owned_env.get_exec_environment(None);

    let cost = eval_contract_cost(&mut env, COSTS.get(&ClarityCostFunctions::AnalysisTypeAnnotate).unwrap().clone(), Some(10));
    assert!(cost == Ok(Value::UInt(11)));

    let cost = eval_contract_cost(&mut env, COSTS.get(&ClarityCostFunctions::StxTransfer).unwrap().clone(), None);
    assert!(cost == Ok(Value::UInt(1)));
}