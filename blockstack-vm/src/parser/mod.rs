use super::representations::SymbolicExpression;

#[derive(Debug)]
pub enum LexItem {
    LeftParen,
    RightParen,
    Atom(String)
}

fn finish_atom(current: &mut Option<String>) -> Option<LexItem> {
    let resp = match current {
        &mut None => {
            None
        },
        &mut Some(ref value) => {
            Some(LexItem::Atom(value.clone()))
        },
    };

    *current = None;
    resp
}

pub fn lex(input: &str) -> Result<Vec<LexItem>, String> {
    let mut result = Vec::new();
    let current = &mut None;
    input.chars().for_each(|c| {
        match c {
            '(' => {
                if let Some(value) = finish_atom(current) {
                    result.push(value);
                }
                result.push(LexItem::LeftParen)
            },
            ')' => {
                if let Some(value) = finish_atom(current) {
                    result.push(value);
                }
                result.push(LexItem::RightParen)
            },
            ' '|'\t'|'\n'|'\r' => {
                if let Some(value) = finish_atom(current) {
                    result.push(value);
                }
            },
            _ => {
                match *current {
                    None => {
                        *current = Some(c.to_string());
                    },
                    Some(ref mut value) => {
                        value.push(c);
                    }
                }
            }
        }
    });

    if let Some(value) = finish_atom(current) {
        result.push(value);
    }

    Ok(result)
}

pub fn parse_lexed(input: &Vec<LexItem>) -> Result<Vec<SymbolicExpression>, String> {
    let mut parse_stack = Vec::new();

    let mut output_list = Vec::new();

    let res = input.iter().try_for_each(|item| {
        match *item {
            LexItem::LeftParen => {
                // start new list.
                let new_list = Vec::new();
                parse_stack.push(new_list);
                Ok(())
            },
            LexItem::RightParen => {
                // end current list.
                if let Some(ref mut value) = parse_stack.pop() {
                    let expression = SymbolicExpression::List((*value).clone().into_boxed_slice());
                    match parse_stack.last_mut() {
                        None => {
                            // no open lists on stack, add current to result.
                            output_list.push(expression)
                        },
                        Some(ref mut list) => {
                            list.push(expression);
                        }
                    };
                    Ok(())
                } else {
                    Err("Tried to close list which isn't open.".to_string())
                }
            },
            LexItem::Atom(ref value) => {
                match parse_stack.last_mut() {
                    None => output_list.push(SymbolicExpression::Atom(value.clone())),
                    Some(ref mut list) => list.push(SymbolicExpression::Atom(value.clone()))
                };
                Ok(())
            }
        }
    });
    match res {
        Ok(_value) => {
            // check unfinished stack:
            if parse_stack.len() > 0 {
                Err("List expressions (..) left opened.".to_string())
            } else {
                Ok(output_list)
            }
        },
        Err(value) => Err(value)
    }
}

pub fn parse(input: &str) -> Result<Vec<SymbolicExpression>, String> {
    match lex(input) {
        Ok(lexed) => parse_lexed(&lexed),
        Err(value) => Err(value)
    }
}