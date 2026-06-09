# Phase 2 Auth And Authorization Completion Plan

> **For mh1pr:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Finish the Phase 2 architecture migration for auth and authorization without breaking the existing public API. The codebase already has `auth/` and `authorization/` directories, so this phase completes the remaining shape, size, and test-locality work instead of repeating the original split.

**Architecture:** Keep `rest_macro_core::{auth, authorization}` as stable public entry points. Move implementation responsibilities into narrower private modules, keep public compatibility through `mod.rs` re-exports, and only introduce roadmap-aligned names such as `password`, `sessions`, `model`, `eval`, `rbac`, `hybrid`, and `assignments` where they reduce mixed responsibilities.

**Baseline observed on 2026-06-09:**
- `auth.rs` and `authorization.rs` no longer exist; both are already directories.
- Most auth files are under 1k lines: `auth/handlers.rs` is 953 lines, `auth/admin.rs` is 682, `auth/db_ops.rs` is 639, and `auth/mod.rs` is 864.
- Authorization still has oversized files: `authorization/engine.rs` is 1206 lines and `authorization/mod.rs` is 1304.
- The roadmap calls the target authorization domain `authz/`, but the current crate exposes `authorization/`; preserve `authorization` externally and treat `authz` naming as internal/forward-looking unless a later phase changes the public surface.

## Task 1: Lock Down Public Compatibility

**Files:**
- `crates/rest_macro_core/src/auth/mod.rs`
- `crates/rest_macro_core/src/authorization/mod.rs`
- `crates/rest_macro_core/src/lib.rs`

**Step 1: Add a compatibility checklist to each module root**

Document that these roots are API facades. The comments should make it clear that downstream imports through `rest_macro_core::auth::*` and `rest_macro_core::authorization::*` are intentionally preserved while internals move.

**Step 2: Keep existing public re-exports stable**

Do not remove or rename public `pub use` items in this task. If an implementation moves, update the `pub use` source path so existing callers compile unchanged.

**Step 3: Identify any public items exported only from oversized modules**

Before splitting `authorization/engine.rs` or moving tests out of `authorization/mod.rs`, note which exported items are sourced from those files. The goal is to move bodies, not change names.

## Task 2: Finish Auth Responsibility Split

**Files:**
- `crates/rest_macro_core/src/auth/mod.rs`
- `crates/rest_macro_core/src/auth/handlers.rs`
- `crates/rest_macro_core/src/auth/helpers.rs`
- `crates/rest_macro_core/src/auth/jwt.rs`
- `crates/rest_macro_core/src/auth/email.rs`
- New: `crates/rest_macro_core/src/auth/password.rs`
- New: `crates/rest_macro_core/src/auth/sessions.rs`

**Step 1: Extract password-specific logic**

Move bcrypt/password policy helpers out of mixed helper or handler code into `auth/password.rs`. Keep the module private unless existing callers need a public re-export.

**Step 2: Extract session and CSRF-specific logic**

Move cookie/session/CSRF helpers into `auth/sessions.rs`. Handler functions should call named helpers instead of carrying protocol details inline.

**Step 3: Keep route handlers focused on HTTP orchestration**

After extraction, `auth/handlers.rs` should mostly parse requests, call auth services/helpers, and shape responses. Avoid mixing JWT, password hashing, email token generation, and cookie mechanics directly in handlers.

**Step 4: Move auth tests closer to owned behavior**

Relocate tests currently embedded in `auth/mod.rs` into module-local `#[cfg(test)]` blocks or a narrow `auth/tests.rs` that delegates by concern. Prefer module-local tests for `jwt`, `password`, `sessions`, `email`, `admin`, and `routing` where helpers are private.

## Task 3: Finish Authorization Responsibility Split

**Files:**
- `crates/rest_macro_core/src/authorization/mod.rs`
- `crates/rest_macro_core/src/authorization/engine.rs`
- `crates/rest_macro_core/src/authorization/types.rs`
- `crates/rest_macro_core/src/authorization/db_ops.rs`
- `crates/rest_macro_core/src/authorization/handlers.rs`
- New: `crates/rest_macro_core/src/authorization/model.rs`
- New: `crates/rest_macro_core/src/authorization/eval.rs`
- New: `crates/rest_macro_core/src/authorization/rbac.rs`
- New: `crates/rest_macro_core/src/authorization/hybrid.rs`
- New: `crates/rest_macro_core/src/authorization/assignments.rs`

**Step 1: Split model types from mixed type definitions**

Move compiled model/domain structs and enums into `authorization/model.rs`. Keep `types.rs` as a compatibility aggregator if that minimizes churn.

**Step 2: Split default evaluation from helpers**

Move the main authorization decision flow into `authorization/eval.rs`. Move RBAC-specific helpers into `authorization/rbac.rs` and hybrid policy helpers into `authorization/hybrid.rs`.

**Step 3: Rename persisted assignment internals without changing exports**

Move runtime assignment CRUD from `db_ops.rs` into `authorization/assignments.rs`, then re-export through existing paths as needed.

**Step 4: Reduce oversized files**

Bring `authorization/engine.rs` and `authorization/mod.rs` below the roadmap target by turning them into narrow orchestration/facade files. If a file remains above 1k lines, document why before merging.

**Step 5: Move authorization tests closer to owned behavior**

Relocate tests from `authorization/mod.rs` into `model`, `eval`, `rbac`, `hybrid`, and `assignments` module tests. Keep integration-style route tests near `handlers` or `routing`.

## Task 4: Update Roadmap Status

**Files:**
- `docs/src/architecture_roadmap.md`

**Step 1: Update Phase 2 current-state language**

Mark the initial directory split as complete and document the remaining completion items: auth password/session extraction, authorization evaluator split, tests moved out of facades, and public compatibility maintained.

**Step 2: Clarify `authorization` versus `authz` naming**

State that this branch preserves `rest_macro_core::authorization` as the public compatibility module and may introduce roadmap-aligned internal names. Defer any public `authz` rename or alias decision to a later compatibility-focused phase.

## Task 5: Verify And Integrate

**Files:**
- `.github/workflows/ci.yml`
- Any files changed by Tasks 1-4

**Step 1: Run targeted checks**

Run the narrowest local checks that cover `rest_macro_core` after each major split. Prefer `cargo check -p rest_macro_core` before broader workspace checks.

**Step 2: Run full CI-equivalent checks before merging to `v1`**

Before merging the feature branch into `v1`, run the workspace feature matrix or push a branch/PR that exercises the existing CI matrix.

**Step 3: Merge only after green checks**

Keep `v1` as the migration integration branch. Merge this branch into `v1` only after the split is implemented and checked.
