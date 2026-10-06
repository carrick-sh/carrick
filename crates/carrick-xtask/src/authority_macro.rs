//! Audited macro grammars: only complete parses expose executable inputs.
use proc_macro2::TokenStream;
use syn::{ext::IdentExt, parse::Parser, visit::Visit};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Audit {
    pub names: Vec<String>,
    grammar: Grammar,
    pub reason: String,
    pub definition_file: Option<String>,
    pub definition_sha256: Option<String>,
}
#[derive(serde::Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Grammar {
    Expressions,
    Vec,
    Matches,
    Items,
    Syscalls,
    Json,
    Offset,
    MailboxOffset,
    Stub,
    ForwardHandlers,
    SyscallTable,
}

pub(super) enum Input {
    File(syn::File),
    Types(Vec<syn::Type>),
    Expressions(Vec<syn::Expr>),
    Matches(Box<syn::Expr>, Box<syn::Pat>, Option<Box<syn::Expr>>),
}
impl Input {
    pub fn visit(&self, visitor: &mut impl for<'ast> Visit<'ast>) {
        match self {
            Self::File(file) => visitor.visit_file(file),
            Self::Types(types) => {
                for ty in types {
                    visitor.visit_type(ty);
                }
            }
            Self::Expressions(expressions) => {
                for expression in expressions {
                    visitor.visit_expr(expression);
                }
            }
            Self::Matches(expression, pattern, guard) => {
                visitor.visit_expr(expression);
                visitor.visit_pat(pattern);
                if let Some(guard) = guard {
                    visitor.visit_expr(guard);
                }
            }
        }
    }
}

fn handler_selector(selector: syn::Ident) -> syn::Result<()> {
    let name = selector.unraw().to_string();
    let vocabulary: std::collections::BTreeMap<String, Vec<String>> = serde_json::from_str(
        include_str!("../../../scripts/migrate/authority-vocabulary.json"),
    )
    .map_err(|error| syn::Error::new(selector.span(), error))?;
    // Exactly these guest syscall handlers share a spelling with raw lock
    // methods. The hashed expansion names the canonical SyscallDispatcher,
    // whose typed SyscallHandler slot cannot contain an ambient function.
    if !matches!(name.as_str(), "read" | "write")
        && (super::authority_dialect::ambient_operation(&name)
            || vocabulary
                .values()
                .flatten()
                .any(|operation| operation == &name))
    {
        return Err(syn::Error::new(
            selector.span(),
            "protected operations are not dispatch metadata",
        ));
    }
    Ok(())
}

pub(super) fn audits() -> Result<Vec<Audit>, serde_json::Error> {
    serde_json::from_str(include_str!(
        "../../../scripts/migrate/authority-macro-allowlist.json"
    ))
}
impl Audit {
    pub fn parse(&self, tokens: TokenStream) -> syn::Result<Input> {
        match self.grammar {
            Grammar::ForwardHandlers => {
                fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Input> {
                    while !input.is_empty() {
                        handler_selector(input.parse()?)?;
                        if !input.is_empty() {
                            let _: syn::Token![,] = input.parse()?;
                        }
                    }
                    Ok(Input::Types(Vec::new()))
                }
                parse.parse2(tokens)
            }
            Grammar::SyscallTable => {
                fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Input> {
                    let attrs = input.call(syn::Attribute::parse_outer)?;
                    for attr in attrs {
                        if !matches!(&attr.meta, syn::Meta::NameValue(value) if value.path.is_ident("doc") && matches!(&value.value, syn::Expr::Lit(lit) if matches!(lit.lit, syn::Lit::Str(_))))
                        {
                            return Err(syn::Error::new_spanned(
                                attr,
                                "only literal doc metadata is audited",
                            ));
                        }
                    }
                    let _: syn::Visibility = input.parse()?;
                    let _: syn::Token![fn] = input.parse()?;
                    let _: syn::Ident = input.parse()?;
                    let _: syn::Token![;] = input.parse()?;
                    while !input.is_empty() {
                        let pattern = syn::Pat::parse_single(input)?;
                        if !matches!(&pattern, syn::Pat::Path(path) if path.qself.is_none()
                            && path.path.segments.len() == 2 && path.path.segments[0].ident == "nr"
                            && path.path.segments.iter().all(|s| matches!(s.arguments, syn::PathArguments::None))
                            && path.path.segments[1].ident.to_string().chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
                        {
                            return Err(syn::Error::new_spanned(
                                pattern,
                                "only nr::UPPERCASE syscall selectors are audited",
                            ));
                        }
                        let _: syn::Token![=>] = input.parse()?;
                        handler_selector(input.parse()?)?;
                        if !input.is_empty() {
                            let _: syn::Token![,] = input.parse()?;
                        }
                    }
                    Ok(Input::Types(Vec::new()))
                }
                parse.parse2(tokens)
            }
            Grammar::Stub => {
                fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Input> {
                    let name: syn::Ident = input.parse()?;
                    let arguments;
                    syn::parenthesized!(arguments in input);
                    let mut typed: Vec<syn::FnArg> = Vec::new();
                    while !arguments.is_empty() {
                        let argument: syn::Ident = arguments.parse()?;
                        let _: syn::Token![:] = arguments.parse()?;
                        let ty: syn::Type = arguments.parse()?;
                        typed.push(syn::parse_quote!(#argument: #ty));
                        if !arguments.is_empty() {
                            let _: syn::Token![,] = arguments.parse()?;
                        }
                    }
                    let mut item: syn::ItemFn = syn::parse_quote!(fn #name(#(#typed),*) {});
                    if input.peek(syn::Token![->]) {
                        item.sig.output = input.parse()?;
                        let _: syn::Token![=>] = input.parse()?;
                        let expression: syn::Expr = input.parse()?;
                        item.block.stmts.push(syn::Stmt::Expr(expression, None));
                    }
                    Ok(Input::File(syn::File {
                        shebang: None,
                        attrs: Vec::new(),
                        items: vec![syn::Item::Fn(item)],
                    }))
                }
                parse.parse2(tokens)
            }
            Grammar::Items => {
                let file: syn::File = syn::parse2(tokens)?;
                if file
                    .items
                    .iter()
                    .any(|item| !matches!(item, syn::Item::Static(_)))
                {
                    return Err(syn::Error::new(
                        proc_macro2::Span::call_site(),
                        "thread_local requires static items",
                    ));
                }
                Ok(Input::File(file))
            }
            Grammar::Expressions => {
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                    .parse2(tokens)
                    .map(|list| Input::Expressions(list.into_iter().collect()))
            }
            Grammar::Vec => {
                fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Input> {
                    if input.is_empty() {
                        return Ok(Input::Expressions(Vec::new()));
                    }
                    let first: syn::Expr = input.parse()?;
                    if input.peek(syn::Token![;]) {
                        let _: syn::Token![;] = input.parse()?;
                        return Ok(Input::Expressions(vec![first, input.parse()?]));
                    }
                    let mut expressions = vec![first];
                    while !input.is_empty() {
                        let _: syn::Token![,] = input.parse()?;
                        if !input.is_empty() {
                            expressions.push(input.parse()?);
                        }
                    }
                    Ok(Input::Expressions(expressions))
                }
                parse.parse2(tokens)
            }
            Grammar::Matches => {
                fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Input> {
                    let expression = input.parse()?;
                    let _: syn::Token![,] = input.parse()?;
                    let pattern = syn::Pat::parse_multi_with_leading_vert(input)?;
                    let guard = if input.peek(syn::Token![if]) {
                        let _: syn::Token![if] = input.parse()?;
                        Some(Box::new(input.parse()?))
                    } else {
                        None
                    };
                    if input.peek(syn::Token![,]) {
                        let _: syn::Token![,] = input.parse()?;
                    }
                    Ok(Input::Matches(
                        Box::new(expression),
                        Box::new(pattern),
                        guard,
                    ))
                }
                parse.parse2(tokens)
            }
            Grammar::Json => {
                fn values(
                    input: syn::parse::ParseStream<'_>,
                    expressions: &mut Vec<syn::Expr>,
                ) -> syn::Result<()> {
                    if input.peek(syn::token::Brace) {
                        let object;
                        syn::braced!(object in input);
                        while !object.is_empty() {
                            expressions.push(object.parse()?);
                            let _: syn::Token![:] = object.parse()?;
                            values(&object, expressions)?;
                            if !object.is_empty() {
                                let _: syn::Token![,] = object.parse()?;
                            }
                        }
                    } else if input.peek(syn::token::Bracket) {
                        let array;
                        syn::bracketed!(array in input);
                        while !array.is_empty() {
                            values(&array, expressions)?;
                            if !array.is_empty() {
                                let _: syn::Token![,] = array.parse()?;
                            }
                        }
                    } else {
                        expressions.push(input.parse()?);
                    }
                    Ok(())
                }
                fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Input> {
                    let mut expressions = Vec::new();
                    values(input, &mut expressions)?;
                    Ok(Input::Expressions(expressions))
                }
                parse.parse2(tokens)
            }
            Grammar::Offset | Grammar::MailboxOffset => {
                fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Input> {
                    let ty: syn::Type = input.parse()?;
                    let _: syn::Token![,] = input.parse()?;
                    let _: syn::Member = input.parse()?;
                    while input.peek(syn::Token![.]) {
                        let _: syn::Token![.] = input.parse()?;
                        let _: syn::Member = input.parse()?;
                    }
                    if input.peek(syn::Token![,]) {
                        let _: syn::Token![,] = input.parse()?;
                    }
                    Ok(Input::Types(vec![ty]))
                }
                // Neither grammar accepts expressions: offset fields and the
                // mailbox const name are metadata, never function references.
                parse.parse2(tokens)
            }
            Grammar::Syscalls => {
                fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Input> {
                    let mut items = Vec::new();
                    while !input.is_empty() {
                        let attributes = input.call(syn::Attribute::parse_outer)?;
                        if input.peek(syn::Ident) {
                            let modifier: syn::Ident = input.parse()?;
                            if modifier.unraw() != "mm_mutation" {
                                return Err(input.error("unknown syscall modifier"));
                            }
                        }
                        let fn_token: syn::Token![fn] = input.parse()?;
                        let name: syn::Ident = input.parse()?;
                        let args;
                        syn::parenthesized!(args in input);
                        let receiver: syn::Ident = args.parse()?;
                        let _: syn::Token![,] = args.parse()?;
                        let context: syn::Ident = args.parse()?;
                        let mut typed = Vec::<syn::FnArg>::new();
                        typed.push(syn::parse_quote!(#receiver: ()));
                        typed.push(syn::parse_quote!(#context: ()));
                        while !args.is_empty() {
                            let _: syn::Token![,] = args.parse()?;
                            if !args.is_empty() {
                                let name: syn::Ident = args.parse()?;
                                let _: syn::Token![:] = args.parse()?;
                                let ty: syn::Type = args.parse()?;
                                typed.push(syn::parse_quote!(#name: #ty));
                            }
                        }
                        let body: syn::Block = input.parse()?;
                        // Only the signature binding differs from expansion;
                        // the body and its source spans are preserved exactly.
                        let mut item: syn::ItemFn = syn::parse_quote!(fn #name(#(#typed),*) #body);
                        item.attrs = attributes;
                        item.sig.fn_token = fn_token;
                        items.push(syn::Item::Fn(item));
                    }
                    Ok(Input::File(syn::File {
                        shebang: None,
                        attrs: Vec::new(),
                        items,
                    }))
                }
                parse.parse2(tokens)
            }
        }
    }
}

pub(super) fn parse(path: &syn::Path, tokens: TokenStream) -> Option<Input> {
    let name = path
        .segments
        .iter()
        .map(|s| s.ident.unraw().to_string())
        .collect::<Vec<_>>()
        .join("::");
    audits()
        .ok()?
        .into_iter()
        .find(|audit| audit.names.contains(&name))?
        .parse(tokens)
        .ok()
}
