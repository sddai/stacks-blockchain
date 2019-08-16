use vm::parser::parse;
use vm::checker::{type_check, CheckError, CheckErrors, AnalysisDatabase};

#[test]
fn test_simple_read_only_violations() {
    // note -- these examples have _type errors_ in addition to read-only errors,
    //    but the read only error should end up taking precedence
    let bad_contracts = [ 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (let ((balance (map-set! tokens (tuple (account tx-sender))
                                              (tuple (balance 10)))))
                 (+ 1 2)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (or (map-insert! tokens (tuple (account tx-sender))
                                             (tuple (balance 10))) 'false))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (tuple (result (map-delete! tokens (tuple (account tx-sender))))))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (map func1 (list 1 2 3)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (map + (list 1 (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))) 3)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (update-balance-and-get-tx-sender)
            (begin              
              (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10)))
              tx-sender))
         (define-read-only (get-token-balance)
            (map-get tokens ((account (update-balance-and-get-tx-sender)))))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (update-balance-and-get-tx-sender)
            (begin              
              (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10)))
              (tuple (account tx-sender))))
         (define-read-only (get-token-balance)
            (map-get tokens (update-balance-and-get-tx-sender)))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (update-balance-and-get-tx-sender)
            (begin              
              (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10)))
              tx-sender))
         (define-read-only (get-token-balance)
            (map-get tokens ((account (update-balance-and-get-tx-sender)))))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (not-reading-only)
            (let ((x 1))
              (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10)))
              x))",
        "(define-map tokens ((account principal)) ((balance int)))
         (define-private (func1) (map-set! tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (fold func1 (list 1 2 3) 1))"];

    for contract in bad_contracts.iter() {
        let mut ast = parse(contract).unwrap();
        let mut db = AnalysisDatabase::memory();
        let err = type_check(&":transient:", &mut ast, &mut db, true).unwrap_err();
        assert_eq!(err.err, CheckErrors::WriteAttemptedInReadOnly)
    }
}

#[test]
fn test_contract_call_read_only_violations() {
    let contract1 = 
        "(define-map tokens ((account principal)) ((balance int)))
         (define-read-only (get-token-balance)
            (get balance (map-get tokens (tuple (account tx-sender))) ))
         (define-public (mint)
            (begin
              (map-set! tokens (tuple (account tx-sender))
                                              (tuple (balance 10)))
              (ok 1)))";
    let bad_caller = 
        "(define-read-only (not-reading-only)
            (contract-call! contract1 mint))";
    let ok_caller =
        "(define-read-only (is-reading-only)
            (eq? 0 (expects! (contract-call! contract1 get-token-balance) 'false)))";

    let mut contract1 = parse(contract1).unwrap();
    let mut bad_caller = parse(bad_caller).unwrap();
    let mut ok_caller = parse(ok_caller).unwrap();

    let mut db = AnalysisDatabase::memory();
    
    type_check(&"contract1", &mut contract1, &mut db, true).unwrap();
    let err = type_check(&"bad_caller", &mut bad_caller, &mut db, true).unwrap_err();
    assert_eq!(err.err, CheckErrors::WriteAttemptedInReadOnly);

    type_check(&"ok_caller", &mut ok_caller, &mut db, true).unwrap();

}