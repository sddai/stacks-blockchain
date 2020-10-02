use std::collections::HashMap;
use super::{ClarityCostFunctionReference, SimpleCostSpecification, TypeCheckCost};
use super::CostFunctions::{Linear, Constant, NLogN, LogN};
use vm::types::{Value, QualifiedContractIdentifier, StandardPrincipalData};
use vm::contexts::{OwnedEnvironment, Environment};
use vm::database::MemoryBackingStore;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::boot::boot_code_id;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub enum ClarityCostFunctionName {
    ANALYSIS_TYPE_ANNOTATE,
    ANALYSIS_TYPE_CHECK,
    ANALYSIS_TYPE_LOOKUP,
    ANALYSIS_VISIT,
    ANALYSIS_ITERABLE_FUNC,
    ANALYSIS_OPTION_CONS,
    ANALYSIS_OPTION_CHECK,
    ANALYSIS_BIND_NAME,
    ANALYSIS_LIST_ITEMS_CHECK,
    ANALYSIS_CHECK_TUPLE_GET,
    ANALYSIS_CHECK_TUPLE_CONS,
    ANALYSIS_TUPLE_ITEMS_CHECK,
    ANALYSIS_CHECK_LET,
    ANALYSIS_LOOKUP_FUNCTION,
    ANALYSIS_LOOKUP_FUNCTION_TYPES,
    ANALYSIS_LOOKUP_VARIABLE_CONST,
    ANALYSIS_LOOKUP_VARIABLE_DEPTH,
    AST_PARSE,
    AST_CYCLE_DETECTION,
    ANALYSIS_STORAGE,
    ANALYSIS_USE_TRAIT_ENTRY,
    ANALYSIS_GET_FUNCTION_ENTRY,
    ANALYSIS_FETCH_CONTRACT_ENTRY,
    LOOKUP_VARIABLE_DEPTH,
    LOOKUP_VARIABLE_SIZE,
    LOOKUP_FUNCTION,
    BIND_NAME,
    INNER_TYPE_CHECK_COST,
    USER_FUNCTION_APPLICATION,
    LET,
    IF,
    ASSERTS,
    MAP,
    FILTER,
    LEN,
    FOLD,
    LIST_CONS,
    TYPE_PARSE_STEP,
    DATA_HASH_COST,
    TUPLE_GET,
    TUPLE_CONS,
    ADD,
    SUB,
    MUL,
    DIV,
    GEQ,
    LEQ,
    LE,
    GE,
    INT_CAST,
    MOD,
    POW,
    SQRTI,
    XOR,
    NOT,
    EQ,
    BEGIN,
    HASH160,
    SHA256,
    SHA512,
    SHA512T256,
    KECCAK256,
    SECP256K1RECOVER,
    SECP256K1VERIFY,
    PRINT,
    SOME_CONS,
    OK_CONS,
    ERR_CONS,
    DEFAULT_TO,
    UNWRAP_RET,
    UNWRAP_ERR_OR_RET,
    IS_OKAY,
    IS_NONE,
    IS_ERR,
    IS_SOME,
    UNWRAP,
    UNWRAP_ERR,
    TRY_RET,
    MATCH,
    OR,
    AND,
    APPEND,
    CONCAT,
    AS_MAX_LEN,
    CONTRACT_CALL,
    CONTRACT_OF,
    PRINCIPAL_OF,
    AT_BLOCK,
    LOAD_CONTRACT,
    CREATE_MAP,
    CREATE_VAR,
    CREATE_NFT,
    CREATE_FT,
    FETCH_ENTRY,
    SET_ENTRY,
    FETCH_VAR,
    SET_VAR,
    CONTRACT_STORAGE,
    BLOCK_INFO,
    STX_BALANCE,
    STX_TRANSFER,
    FT_MINT,
    FT_TRANSFER,
    FT_BALANCE,
    NFT_MINT,
    NFT_TRANSFER,
    NFT_OWNER,
}

fn boot_function(function_name: &'static str) -> ClarityCostFunctionReference {
    ClarityCostFunctionReference {
        contract_id: boot_code_id("costs"),
        function_name,
    }
}

lazy_static! {
    pub static ref COSTS: HashMap<ClarityCostFunctionName, ClarityCostFunctionReference> = {
        let mut m = HashMap::new();
        m.insert(ClarityCostFunctionName::ANALYSIS_TYPE_ANNOTATE, boot_function("cost_analysis_type_annotate"));
        m.insert(ClarityCostFunctionName::ANALYSIS_TYPE_CHECK, boot_function("cost_analysis_type_check"));
        m.insert(ClarityCostFunctionName::ANALYSIS_TYPE_LOOKUP, boot_function("cost_analysis_type_lookup"));
        m.insert(ClarityCostFunctionName::ANALYSIS_VISIT, boot_function("cost_analysis_visit"));
        m.insert(ClarityCostFunctionName::ANALYSIS_ITERABLE_FUNC, boot_function("cost_analysis_iterable_func"));
        m.insert(ClarityCostFunctionName::ANALYSIS_OPTION_CONS, boot_function("cost_analysis_option_cons"));
        m.insert(ClarityCostFunctionName::ANALYSIS_OPTION_CHECK, boot_function("cost_analysis_option_check"));
        m.insert(ClarityCostFunctionName::ANALYSIS_BIND_NAME, boot_function("cost_analysis_bind_name"));
        m.insert(ClarityCostFunctionName::ANALYSIS_LIST_ITEMS_CHECK, boot_function("cost_analysis_list_items_check"));
        m.insert(ClarityCostFunctionName::ANALYSIS_CHECK_TUPLE_GET, boot_function("cost_analysis_check_tuple_get"));
        m.insert(ClarityCostFunctionName::ANALYSIS_CHECK_TUPLE_CONS, boot_function("cost_analysis_check_tuple_cons"));
        m.insert(ClarityCostFunctionName::ANALYSIS_TUPLE_ITEMS_CHECK, boot_function("cost_analysis_tuple_items_check"));
        m.insert(ClarityCostFunctionName::ANALYSIS_CHECK_LET, boot_function("cost_analysis_check_let"));
        m.insert(ClarityCostFunctionName::ANALYSIS_LOOKUP_FUNCTION, boot_function("cost_analysis_lookup_function"));
        m.insert(ClarityCostFunctionName::ANALYSIS_LOOKUP_FUNCTION_TYPES, boot_function("cost_analysis_lookup_function_types"));
        m.insert(ClarityCostFunctionName::ANALYSIS_LOOKUP_VARIABLE_CONST, boot_function("cost_analysis_lookup_variable_const"));
        m.insert(ClarityCostFunctionName::ANALYSIS_LOOKUP_VARIABLE_DEPTH, boot_function("cost_analysis_lookup_variable_depth"));
        m.insert(ClarityCostFunctionName::AST_PARSE, boot_function("cost_ast_parse"));
        m.insert(ClarityCostFunctionName::AST_CYCLE_DETECTION, boot_function("cost_ast_cycle_detection"));
        m.insert(ClarityCostFunctionName::ANALYSIS_STORAGE, boot_function("cost_analysis_storage"));
        m.insert(ClarityCostFunctionName::ANALYSIS_USE_TRAIT_ENTRY, boot_function("cost_analysis_use_trait_entry"));
        m.insert(ClarityCostFunctionName::ANALYSIS_GET_FUNCTION_ENTRY, boot_function("cost_analysis_get_function_entry"));
        m.insert(ClarityCostFunctionName::ANALYSIS_FETCH_CONTRACT_ENTRY, boot_function("cost_analysis_fetch_contract_entry"));
        m.insert(ClarityCostFunctionName::LOOKUP_VARIABLE_DEPTH, boot_function("cost_lookup_variable_depth"));
        m.insert(ClarityCostFunctionName::LOOKUP_VARIABLE_SIZE, boot_function("cost_lookup_variable_size"));
        m.insert(ClarityCostFunctionName::LOOKUP_FUNCTION, boot_function("cost_lookup_function"));
        m.insert(ClarityCostFunctionName::BIND_NAME, boot_function("cost_bind_name"));
        m.insert(ClarityCostFunctionName::INNER_TYPE_CHECK_COST, boot_function("cost_inner_type_check_cost"));
        m.insert(ClarityCostFunctionName::USER_FUNCTION_APPLICATION, boot_function("cost_user_function_application"));
        m.insert(ClarityCostFunctionName::LET, boot_function("cost_let"));
        m.insert(ClarityCostFunctionName::IF, boot_function("cost_if"));
        m.insert(ClarityCostFunctionName::ASSERTS, boot_function("cost_asserts"));
        m.insert(ClarityCostFunctionName::MAP, boot_function("cost_map"));
        m.insert(ClarityCostFunctionName::FILTER, boot_function("cost_filter"));
        m.insert(ClarityCostFunctionName::LEN, boot_function("cost_len"));
        m.insert(ClarityCostFunctionName::FOLD, boot_function("cost_fold"));
        m.insert(ClarityCostFunctionName::LIST_CONS, boot_function("cost_list_cons"));
        m.insert(ClarityCostFunctionName::TYPE_PARSE_STEP, boot_function("cost_type_parse_step"));
        m.insert(ClarityCostFunctionName::DATA_HASH_COST, boot_function("cost_data_hash_cost"));
        m.insert(ClarityCostFunctionName::TUPLE_GET, boot_function("cost_tuple_get"));
        m.insert(ClarityCostFunctionName::TUPLE_CONS, boot_function("cost_tuple_cons"));
        m.insert(ClarityCostFunctionName::ADD, boot_function("cost_add"));
        m.insert(ClarityCostFunctionName::SUB, boot_function("cost_sub"));
        m.insert(ClarityCostFunctionName::MUL, boot_function("cost_mul"));
        m.insert(ClarityCostFunctionName::DIV, boot_function("cost_div"));
        m.insert(ClarityCostFunctionName::GEQ, boot_function("cost_geq"));
        m.insert(ClarityCostFunctionName::LEQ, boot_function("cost_leq"));
        m.insert(ClarityCostFunctionName::LE, boot_function("cost_le"));
        m.insert(ClarityCostFunctionName::GE, boot_function("cost_ge"));
        m.insert(ClarityCostFunctionName::INT_CAST, boot_function("cost_int_cast"));
        m.insert(ClarityCostFunctionName::MOD, boot_function("cost_mod"));
        m.insert(ClarityCostFunctionName::POW, boot_function("cost_pow"));
        m.insert(ClarityCostFunctionName::SQRTI, boot_function("cost_sqrti"));
        m.insert(ClarityCostFunctionName::XOR, boot_function("cost_xor"));
        m.insert(ClarityCostFunctionName::NOT, boot_function("cost_not"));
        m.insert(ClarityCostFunctionName::EQ, boot_function("cost_eq"));
        m.insert(ClarityCostFunctionName::BEGIN, boot_function("cost_begin"));
        m.insert(ClarityCostFunctionName::HASH160, boot_function("cost_hash160"));
        m.insert(ClarityCostFunctionName::SHA256, boot_function("cost_sha256"));
        m.insert(ClarityCostFunctionName::SHA512, boot_function("cost_sha512"));
        m.insert(ClarityCostFunctionName::SHA512T256, boot_function("cost_sha512t256"));
        m.insert(ClarityCostFunctionName::KECCAK256, boot_function("cost_keccak256"));
        m.insert(ClarityCostFunctionName::SECP256K1RECOVER, boot_function("cost_secp256k1recover"));
        m.insert(ClarityCostFunctionName::SECP256K1VERIFY, boot_function("cost_secp256k1verify"));
        m.insert(ClarityCostFunctionName::PRINT, boot_function("cost_print"));
        m.insert(ClarityCostFunctionName::SOME_CONS, boot_function("cost_some_cons"));
        m.insert(ClarityCostFunctionName::OK_CONS, boot_function("cost_ok_cons"));
        m.insert(ClarityCostFunctionName::ERR_CONS, boot_function("cost_err_cons"));
        m.insert(ClarityCostFunctionName::DEFAULT_TO, boot_function("cost_default_to"));
        m.insert(ClarityCostFunctionName::UNWRAP_RET, boot_function("cost_unwrap_ret"));
        m.insert(ClarityCostFunctionName::UNWRAP_ERR_OR_RET, boot_function("cost_unwrap_err_or_ret"));
        m.insert(ClarityCostFunctionName::IS_OKAY, boot_function("cost_is_okay"));
        m.insert(ClarityCostFunctionName::IS_NONE, boot_function("cost_is_none"));
        m.insert(ClarityCostFunctionName::IS_ERR, boot_function("cost_is_err"));
        m.insert(ClarityCostFunctionName::IS_SOME, boot_function("cost_is_some"));
        m.insert(ClarityCostFunctionName::UNWRAP, boot_function("cost_unwrap"));
        m.insert(ClarityCostFunctionName::UNWRAP_ERR, boot_function("cost_unwrap_err"));
        m.insert(ClarityCostFunctionName::TRY_RET, boot_function("cost_try_ret"));
        m.insert(ClarityCostFunctionName::MATCH, boot_function("cost_match"));
        m.insert(ClarityCostFunctionName::OR, boot_function("cost_or"));
        m.insert(ClarityCostFunctionName::AND, boot_function("cost_and"));
        m.insert(ClarityCostFunctionName::APPEND, boot_function("cost_append"));
        m.insert(ClarityCostFunctionName::CONCAT, boot_function("cost_concat"));
        m.insert(ClarityCostFunctionName::AS_MAX_LEN, boot_function("cost_as_max_len"));
        m.insert(ClarityCostFunctionName::CONTRACT_CALL, boot_function("cost_contract_call"));
        m.insert(ClarityCostFunctionName::CONTRACT_OF, boot_function("cost_contract_of"));
        m.insert(ClarityCostFunctionName::PRINCIPAL_OF, boot_function("cost_principal_of"));
        m.insert(ClarityCostFunctionName::AT_BLOCK, boot_function("cost_at_block"));
        m.insert(ClarityCostFunctionName::LOAD_CONTRACT, boot_function("cost_load_contract"));
        m.insert(ClarityCostFunctionName::CREATE_MAP, boot_function("cost_create_map"));
        m.insert(ClarityCostFunctionName::CREATE_VAR, boot_function("cost_create_var"));
        m.insert(ClarityCostFunctionName::CREATE_NFT, boot_function("cost_create_nft"));
        m.insert(ClarityCostFunctionName::CREATE_FT, boot_function("cost_create_ft"));
        m.insert(ClarityCostFunctionName::FETCH_ENTRY, boot_function("cost_fetch_entry"));
        m.insert(ClarityCostFunctionName::SET_ENTRY, boot_function("cost_set_entry"));
        m.insert(ClarityCostFunctionName::FETCH_VAR, boot_function("cost_fetch_var"));
        m.insert(ClarityCostFunctionName::SET_VAR, boot_function("cost_set_var"));
        m.insert(ClarityCostFunctionName::CONTRACT_STORAGE, boot_function("cost_contract_storage"));
        m.insert(ClarityCostFunctionName::BLOCK_INFO, boot_function("cost_block_info"));
        m.insert(ClarityCostFunctionName::STX_BALANCE, boot_function("cost_stx_balance"));
        m.insert(ClarityCostFunctionName::STX_TRANSFER, boot_function("cost_stx_transfer"));
        m.insert(ClarityCostFunctionName::FT_MINT, boot_function("cost_ft_mint"));
        m.insert(ClarityCostFunctionName::FT_TRANSFER, boot_function("cost_ft_transfer"));
        m.insert(ClarityCostFunctionName::FT_BALANCE, boot_function("cost_ft_balance"));
        m.insert(ClarityCostFunctionName::NFT_MINT, boot_function("cost_nft_mint"));
        m.insert(ClarityCostFunctionName::NFT_TRANSFER, boot_function("cost_nft_transfer"));
        m.insert(ClarityCostFunctionName::NFT_OWNER, boot_function("cost_nft_owner"));
        m
    };
}

fn eval_contract_cost(
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

    let cost = eval_contract_cost(&mut env, COSTS.get(&ClarityCostFunctionName::ANALYSIS_TYPE_ANNOTATE).unwrap().clone(), Some(10));
    assert!(cost == Ok(Value::UInt(11)));

    let cost = eval_contract_cost(&mut env, COSTS.get(&ClarityCostFunctionName::STX_TRANSFER).unwrap().clone(), None);
    assert!(cost == Ok(Value::UInt(1)));
}