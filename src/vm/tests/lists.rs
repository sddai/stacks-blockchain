use vm::types::{Value, TypeSignature};

use vm::execute;
use vm::errors::{UncheckedError, RuntimeErrorType, Error};

#[test]
fn test_simple_list_admission() {
    let defines =
        "(define-private (square (x int)) (* x x))
         (define-private (square-list (x (list 4 int))) (map square x))";
    let t1 = format!("{} (square-list (list 1 2 3 4))", defines);
    let t2 = format!("{} (square-list (list))", defines);
    let t3 = format!("{} (square-list (list 1 2 3 4 5))", defines);
    

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(4),
        Value::Int(9),
        Value::Int(16)]).unwrap();

    assert_eq!(expected, execute(&t1).unwrap().unwrap());
    assert_eq!(Value::list_from(vec![]).unwrap(), execute(&t2).unwrap().unwrap());
    let err = execute(&t3).unwrap_err();
    assert!(match err {
        Error::Unchecked(UncheckedError::TypeError(_, _)) => true,
        _ => {
            eprintln!("Expected TypeError, but found: {:?}", err);
            false
        }
    });
}

#[test]
fn test_simple_map() {
    let test1 =
        "(define-private (square (x int)) (* x x))
         (map square (list 1 2 3 4))";

    let expected = Value::list_from(vec![
        Value::Int(1),
        Value::Int(4),
        Value::Int(9),
        Value::Int(16)]).unwrap();

    assert_eq!(expected, execute(test1).unwrap().unwrap());

    // let's test lists of lists.
    let test2 = "(define-private (multiply (x int) (acc int)) (* x acc))
                 (define-private (multiply-all (x (list 10 int))) (fold multiply x 1))
                 (map multiply-all (list (list 1 1 1) (list 2 2 1) (list 3 3) (list 2 2 2 2)))";
    assert_eq!(expected, execute(test2).unwrap().unwrap());

    // let's test empty lists.
    let test2 = "(define-private (double (x int)) (* x 2))
                 (map double (list))";
    assert_eq!(Value::list_from(vec![]).unwrap(), execute(test2).unwrap().unwrap());

}

#[test]
fn test_simple_filter() {
    let test1 =
"    (define-private (test (x int)) (eq? 0 (mod x 2)))
    (filter test (list 1 2 3 4 5))";

    let bad_tests = [
        "(filter 123 (list 123))",     // must have function name supplied
        "(filter not (list 123) 3)",  // must be 2 args
        "(filter +)",  // must be 2 args
        "(filter not 'false)",       // must supply list
        "(filter - (list 1 2 3))"]; // must return bool


    let expected = Value::list_from(vec![
        Value::Int(2),
        Value::Int(4)]).unwrap();

    assert_eq!(expected, execute(test1).unwrap().unwrap());

    for t in bad_tests.iter() {
        execute(t).unwrap_err();
    }
}

#[test]
fn test_list_tuple_admission() {
    let test = 
        "(define-private (bufferize (x int)) (if (eq? x 1) \"abc\" \"ab\"))
         (define-private (tuplize (x int))
           (tuple (value (bufferize x))))
         (map tuplize (list 0 1 0 1 0 1))";

    let expected_type = 
        "(list (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\"))
               (tuple (value \"012\")))";

    let not_expected_type = 
        "(list (tuple (value \"01\"))
               (tuple (value \"02\"))
               (tuple (value \"12\"))
               (tuple (value \"12\"))
               (tuple (value \"01\"))
               (tuple (value \"02\")))";

    
    let result_type = TypeSignature::type_of(&execute(test).unwrap().unwrap());
    let expected_type = TypeSignature::type_of(&execute(expected_type).unwrap().unwrap());
    let testing_value = &execute(not_expected_type).unwrap().unwrap();
    let not_expected_type = TypeSignature::type_of(testing_value);

    assert_eq!(expected_type, result_type);
    assert!(not_expected_type != result_type);
    assert!(result_type.admits(&testing_value));
}

#[test]
fn test_simple_folds() {
    let test1 =
        "(define-private (multiply-all (x int) (acc int)) (* x acc))
         (fold multiply-all (list 1 2 3 4) 1)";

    let expected = Value::Int(24);

    assert_eq!(expected, execute(test1).unwrap().unwrap());
}

#[test]
fn test_construct_bad_list() {
    let test1 = "(list 1 2 3 'true)";
    assert!(
        match execute(test1).unwrap_err() {
            Error::Runtime(RuntimeErrorType::BadTypeConstruction, _) => true,
            _ => false
        });

    let test2 = "(define-private (bad-function (x int)) (if (eq? x 1) 'true x))
                 (map bad-function (list 0 1 2 3))";
    assert!(
        match execute(test2).unwrap_err() {
            Error::Runtime(RuntimeErrorType::BadTypeConstruction, _) => true,
            _ => false
        });

    let bad_2d_list = "(list (list 1 2 3) (list 'true 'false 'true))";
    let bad_high_order_list = "(list (list 1 2 3) (list (list 1 2 3)))";

    let expected_err_1 = match execute(bad_2d_list).unwrap_err() {
        Error::Runtime(RuntimeErrorType::BadTypeConstruction, _) => true,
        _ => false
    };

    assert!(expected_err_1);

    let expected_err_2 = match execute(bad_high_order_list).unwrap_err() {
        Error::Runtime(RuntimeErrorType::BadTypeConstruction, _) => true,
        _ => false
    };

   assert!(expected_err_2);
}

#[test]
fn test_eval_func_arg_panic() {
    let test1 = "(fold (lambda (x y) (* x y)) (list 1 2 3 4) 1)";
    let e: Error = UncheckedError::ExpectedFunctionName.into();
    assert_eq!(e, execute(test1).unwrap_err());

    let test2 = "(map (lambda (x) (* x x)) (list 1 2 3 4))";
    let e: Error = UncheckedError::ExpectedFunctionName.into();
    assert_eq!(e, execute(test2).unwrap_err());

    let test3 = "(map square (list 1 2 3 4) 2)";
    let e: Error = UncheckedError::IncorrectArgumentCount(2, 3).into();
    assert_eq!(e, execute(test3).unwrap_err());

    let test4 = "(define-private (multiply-all (x int) (acc int)) (* x acc))
         (fold multiply-all (list 1 2 3 4))";
    let e: Error = UncheckedError::IncorrectArgumentCount(3, 2).into();
    assert_eq!(e, execute(test4).unwrap_err());
}