use quote::ToTokens;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use syn::{spanned::Spanned, visit::Visit};
fn absent(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("test")
            || (a.path().is_ident("cfg") && {
                let t = a.meta.to_token_stream().to_string().replace(' ', "");
                t == "cfg(test)" || t.starts_with("cfg(all(test,")
            })
    })
}
struct Scan<'a> {
    root: PathBuf,
    excluded: &'a mut BTreeMap<PathBuf, BTreeSet<usize>>,
    file: PathBuf,
    only_test: bool,
}
impl Scan<'_> {
    fn items(&mut self, items: &[syn::Item]) {
        for i in items {
            self.visit_item(i);
        }
    }
    fn external(&mut self, m: &syn::ItemMod, only: bool) {
        let mut path = None;
        for a in &m.attrs {
            if let syn::Meta::NameValue(v) = &a.meta {
                if v.path.is_ident("path") {
                    if let syn::Expr::Lit(e) = &v.value {
                        if let syn::Lit::Str(s) = &e.lit {
                            path = Some(self.file.parent().unwrap().join(s.value()));
                        }
                    }
                }
            }
        }
        let p = path.unwrap_or_else(|| {
            let a = self.root.join(format!("{}.rs", m.ident));
            if a.exists() {
                a
            } else {
                self.root.join(m.ident.to_string()).join("mod.rs")
            }
        });
        if p.exists() {
            scan_file(&p, only, self.excluded);
        }
    }
}
impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_field(&mut self, x: &'ast syn::Field) {
        if absent(&x.attrs) {
            let span = x.span();
            self.excluded
                .entry(self.file.clone())
                .or_default()
                .extend(span.start().line..=span.end().line);
        } else {
            syn::visit::visit_field(self, x)
        }
    }
    fn visit_field_value(&mut self, x: &'ast syn::FieldValue) {
        if absent(&x.attrs) {
            let span = x.span();
            self.excluded
                .entry(self.file.clone())
                .or_default()
                .extend(span.start().line..=span.end().line);
        } else {
            syn::visit::visit_field_value(self, x)
        }
    }
    fn visit_expr(&mut self, x: &'ast syn::Expr) {
        let attrs = match x {
            syn::Expr::Block(x) => &x.attrs,
            syn::Expr::If(x) => &x.attrs,
            _ => &[][..],
        };
        if absent(attrs) {
            let span = x.span();
            self.excluded
                .entry(self.file.clone())
                .or_default()
                .extend(span.start().line..=span.end().line);
        } else {
            syn::visit::visit_expr(self, x)
        }
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs = match item {
            syn::Item::Const(x) => &x.attrs,
            syn::Item::Enum(x) => &x.attrs,
            syn::Item::Fn(x) => &x.attrs,
            syn::Item::Impl(x) => &x.attrs,
            syn::Item::Mod(x) => &x.attrs,
            syn::Item::Struct(x) => &x.attrs,
            syn::Item::Use(x) => &x.attrs,
            syn::Item::Static(x) => &x.attrs,
            syn::Item::Trait(x) => &x.attrs,
            syn::Item::Type(x) => &x.attrs,
            syn::Item::Macro(x) => &x.attrs,
            _ => &[][..],
        };
        let only = self.only_test || absent(attrs);
        if only {
            let span = item.span();
            self.excluded
                .entry(self.file.clone())
                .or_default()
                .extend(span.start().line..=span.end().line);
        }
        if let syn::Item::Mod(m) = item {
            if let Some((_, items)) = &m.content {
                let old_root = self.root.clone();
                let old = self.only_test;
                self.root = self.root.join(m.ident.to_string());
                self.only_test = only;
                self.items(items);
                self.root = old_root;
                self.only_test = old;
            } else {
                self.external(m, only);
            }
        } else if !only {
            syn::visit::visit_item(self, item);
        }
    }
}
fn scan_file(p: &Path, only: bool, ex: &mut BTreeMap<PathBuf, BTreeSet<usize>>) {
    let s = fs::read_to_string(p).unwrap();
    let f = syn::parse_file(&s).unwrap();
    let only = only || absent(&f.attrs);
    if only {
        ex.entry(p.into())
            .or_default()
            .extend(1..=s.lines().count());
    }
    let root = if matches!(
        p.file_stem().unwrap().to_str().unwrap(),
        "lib" | "main" | "mod"
    ) {
        p.parent().unwrap().into()
    } else {
        p.with_extension("")
    };
    Scan {
        root,
        excluded: ex,
        file: p.into(),
        only_test: only,
    }
    .items(&f.items);
}
fn files(p: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(p).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            files(&p, out)
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p)
        }
    }
}
fn main() {
    let base = PathBuf::from(std::env::args().nth(1).unwrap());
    let mut grand = 0;
    for name in ["carrick-el1", "carrick-el1-abi", "carrick-aarch64"] {
        let mut all = vec![];
        files(&base.join("crates").join(name).join("src"), &mut all);
        let mut ex = BTreeMap::new();
        for p in &all {
            scan_file(p, false, &mut ex);
        }
        let mut count = 0;
        let mut total = 0;
        for p in &all {
            let s = fs::read_to_string(p).unwrap();
            total += s.lines().count();
            let empty = BTreeSet::new();
            let skipped = ex.get(p).unwrap_or(&empty);
            count += s
                .lines()
                .enumerate()
                .filter(|(i, _)| !skipped.contains(&(i + 1)))
                .count();
        }
        grand += count;
        println!("{name}: production_physical_lines={count}, all_src_lines={total}");
    }
    println!("TOTAL={grand}");
}
