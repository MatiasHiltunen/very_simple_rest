use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use rest_macro_core::compiler;
use syn::{DeriveInput, LitStr, Path, parse_macro_input};

#[proc_macro_derive(RestApi, attributes(rest_api, require_role, relation, row_policy))]
pub fn rest_api_macro(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_result(compiler::expand_derive(input, runtime_crate_path()))
}

#[proc_macro]
pub fn rest_api_from_eon(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LitStr);
    expand_result(compiler::expand_eon_file(input, runtime_crate_path()))
}

#[proc_macro]
pub fn rest_api_eon(input: TokenStream) -> TokenStream {
    rest_api_from_eon(input)
}

fn runtime_crate_path() -> Path {
    let crate_name = match crate_name("very_simple_rest") {
        Ok(FoundCrate::Name(name)) => name,
        Ok(FoundCrate::Itself) | Err(_) => "very_simple_rest".to_owned(),
    };

    syn::parse_str(&crate_name).expect("valid crate path")
}

fn expand_result(result: syn::Result<proc_macro2::TokenStream>) -> TokenStream {
    match result {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}
