#![cfg(test)]
extern crate std;

// The "missing authorization" tests below need to mock only one party's
// signature and leave the other unmocked — `mock_all_auths()` approves every
// `require_auth`/`require_auth_for_args` call regardless of identity, so it
// can't express "the user signed but the relayer didn't" (or vice versa).
// Those tests build the authorization tree by hand with `mock_auths`,
// mirroring OZ's own `examples/fee-forwarder-permissioned` test suite.
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, Address, Env, IntoVal, MuxedAddress, String, Symbol, TryFromVal, TryIntoVal, Val, Vec,
};
use stellar_tokens::fungible::{Base, FungibleToken};

use super::{FeeForwarder, FeeForwarderClient};

#[contract]
pub struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn __constructor(e: &Env, to: Address) {
        Base::set_metadata(e, 7, String::from_str(e, "Mock Token"), String::from_str(e, "MOCK"));
        Base::mint(e, &to, 1_000_000_000);
    }
}

#[contractimpl(contracttrait)]
impl FungibleToken for MockToken {
    type ContractType = Base;
}

#[contract]
pub struct MockTarget;

#[contractimpl]
impl MockTarget {
    pub fn greet(e: Env) -> String {
        String::from_str(&e, "hello")
    }

    pub fn fail(_e: Env) -> String {
        panic!("target intentionally fails")
    }

    /// Requires `caller`'s own authorization, independent of whoever signed
    /// the enclosing `forward()` call. Mirrors a real Latch smart-account
    /// operation forwarded through this contract, which needs the account's
    /// own signer authorization as a sub-invocation, not just a no-auth call
    /// like `greet()`.
    pub fn act_as(e: Env, caller: Address) -> String {
        caller.require_auth();
        String::from_str(&e, "authorized")
    }
}

struct Setup<'a> {
    fee_forwarder: FeeForwarderClient<'a>,
    token: MockTokenClient<'a>,
    target: MockTargetClient<'a>,
    admin: Address,
    manager: Address,
    user: Address,
    relayer: Address,
    fee_amount: i128,
    max_fee_amount: i128,
}

fn setup(e: &Env) -> Setup<'_> {
    let admin = Address::generate(e);
    let manager = Address::generate(e);
    let user = Address::generate(e);
    let relayer = Address::generate(e);

    let fee_forwarder_id =
        e.register(FeeForwarder, (admin.clone(), manager.clone(), vec![e, relayer.clone()]));
    let token_id = e.register(MockToken, (user.clone(),));
    let target_id = e.register(MockTarget, ());

    Setup {
        fee_forwarder: FeeForwarderClient::new(e, &fee_forwarder_id),
        token: MockTokenClient::new(e, &token_id),
        target: MockTargetClient::new(e, &target_id),
        admin,
        manager,
        user,
        relayer,
        fee_amount: 100_000,
        max_fee_amount: 150_000,
    }
}

/// Builds the (user, relayer) `forward` invocations `mock_auths` expects.
/// Returned by value — a `MockAuth` borrowing these must be constructed by
/// the caller, since a `MockAuthInvoke` built and borrowed inside this
/// function would dangle once it returns.
fn forward_invokes<'a>(
    s: &'a Setup<'a>,
    e: &'a Env,
    fee_amount: i128,
    fn_name: &'a Symbol,
    fn_args: &'a Vec<Val>,
) -> (MockAuthInvoke<'a>, MockAuthInvoke<'a>) {
    let current_ledger = e.ledger().sequence();
    let user_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
        )
            .into_val(e),
        sub_invokes: &[],
    };
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(e),
        sub_invokes: &[],
    };
    (user_invoke, relayer_invoke)
}

/// Pre-approves `max_fee_amount` directly on the token (authorized by
/// `user`), so `forward`'s Lazy approval strategy sees a sufficient
/// allowance and doesn't need an `approve` sub-invocation folded into the
/// `forward` authorization tree.
fn pre_approve(s: &Setup, e: &Env) {
    let current_ledger = e.ledger().sequence();
    s.token
        .mock_auths(&[MockAuth {
            address: &s.user,
            invoke: &MockAuthInvoke {
                contract: &s.token.address,
                fn_name: "approve",
                args: (
                    s.user.clone(),
                    s.fee_forwarder.address.clone(),
                    s.max_fee_amount,
                    current_ledger,
                )
                    .into_val(e),
                sub_invokes: &[],
            },
        }])
        .approve(&s.user, &s.fee_forwarder.address, &s.max_fee_amount, &current_ledger);
}

// ── forward: happy path ─────────────────────────────────────────────────────

#[test]
fn forward_collects_fee_and_invokes_target() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];

    let initial_user_balance = s.token.balance(&s.user);
    let current_ledger = e.ledger().sequence();

    let (user_invoke, relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    let res: String = s
        .fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        )
        .try_into_val(&e)
        .unwrap();

    assert_eq!(res, String::from_str(&e, "hello"));
    assert_eq!(s.token.balance(&s.user), initial_user_balance - s.fee_amount);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), s.fee_amount);
}

// ── forward: dual-authorization requirement ─────────────────────────────────

#[test]
#[should_panic]
fn forward_rejects_missing_user_auth() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let (_user_invoke, relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let relayer_auth = MockAuth { address: &s.relayer, invoke: &relayer_invoke };

    s.fee_forwarder.mock_auths(&[relayer_auth]).forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
#[should_panic]
fn forward_rejects_missing_relayer_auth() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let (user_invoke, _relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let user_auth = MockAuth { address: &s.user, invoke: &user_invoke };

    s.fee_forwarder.mock_auths(&[user_auth]).forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

// ── forward: business-rule rejections ───────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #5003)")]
fn forward_rejects_fee_exceeding_max() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();
    let excessive_fee = s.max_fee_amount + 1;

    s.fee_forwarder.forward(
        &s.token.address,
        &excessive_fee,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #5000)")]
fn forward_rejects_non_allowlisted_fee_token() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Enabling any token turns the allowlist on; `s.token` was never added.
    let other_token = Address::generate(&e);
    s.fee_forwarder.enable_fee_token(&other_token, &s.manager);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn forward_rejects_non_executor_caller() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_executor = Address::generate(&e);
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &not_executor,
    );
}

// ── forward: atomicity ──────────────────────────────────────────────────────

#[test]
fn forward_reverts_fee_collection_when_target_call_fails() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let fn_name = Symbol::new(&e, "fail");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let initial_user_balance = s.token.balance(&s.user);
    let initial_contract_balance = s.token.balance(&s.fee_forwarder.address);

    let result = s.fee_forwarder.try_forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );

    assert!(result.is_err());
    assert_eq!(s.token.balance(&s.user), initial_user_balance);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), initial_contract_balance);
    assert_eq!(s.token.allowance(&s.user, &s.fee_forwarder.address), 0);
}

// ── forward: nested target authorization ────────────────────────────────────
//
// Covers the realistic case OZ's own reference suite exercises as
// `forward_two_subinvokes`: the target call itself requires its own
// `require_auth()`, folded as a sub-invocation of the same authorization
// tree `user` signs for `forward()` — not a separate top-level entry.

#[test]
fn forward_authorizes_target_call_requiring_nested_auth() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "act_as");
    let fn_args: Vec<Val> = vec![&e, s.user.clone().into_val(&e)];
    let current_ledger = e.ledger().sequence();

    let target_invoke = MockAuthInvoke {
        contract: &s.target.address,
        fn_name: "act_as",
        args: (s.user.clone(),).into_val(&e),
        sub_invokes: &[],
    };
    let user_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
        )
            .into_val(&e),
        sub_invokes: &[target_invoke],
    };
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    let res: String = s
        .fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        )
        .try_into_val(&e)
        .unwrap();

    assert_eq!(res, String::from_str(&e, "authorized"));
}

#[test]
#[should_panic]
fn forward_rejects_target_call_missing_nested_auth() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "act_as");
    let fn_args: Vec<Val> = vec![&e, s.user.clone().into_val(&e)];
    let current_ledger = e.ledger().sequence();

    // Same signed tree as `forward_collects_fee_and_invokes_target`, but
    // without the target's sub-invocation: `user` authorizes `forward()`
    // itself, yet the nested `caller.require_auth()` inside `act_as` has
    // nothing to match, so it must fail even though the outer call is
    // authorized.
    let (user_invoke, relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder.mock_auths(&auths).forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

// ── fee token allowlist: manager-gated ──────────────────────────────────────

#[test]
fn enable_and_disable_fee_token_by_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.enable_fee_token(&s.token.address, &s.manager);
    // A second allowlisted token, so disabling `s.token` below leaves the
    // allowlist enabled (it only turns itself off once *no* token remains
    // allowed) rather than falling back open to "all tokens allowed".
    s.fee_forwarder.enable_fee_token(&Address::generate(&e), &s.manager);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Allowed while enabled.
    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );

    s.fee_forwarder.disable_fee_token(&s.token.address, &s.manager);

    let result = s.fee_forwarder.try_forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn enable_fee_token_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.enable_fee_token(&s.token.address, &not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn disable_fee_token_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.enable_fee_token(&s.token.address, &s.manager);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.disable_fee_token(&s.token.address, &not_manager);
}

// ── sweep_tokens: manager-gated ─────────────────────────────────────────────

#[test]
fn sweep_tokens_by_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );

    let recipient = Address::generate(&e);
    let swept = s.fee_forwarder.sweep_tokens(&s.token.address, &recipient, &s.manager);

    assert_eq!(swept, s.fee_amount);
    assert_eq!(s.token.balance(&recipient), s.fee_amount);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn sweep_tokens_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    let recipient = Address::generate(&e);
    s.fee_forwarder.sweep_tokens(&s.token.address, &recipient, &not_manager);
}

// ── constructor role wiring ──────────────────────────────────────────────────

#[test]
fn constructor_grants_admin_manager_and_executor_roles() {
    let e = Env::default();
    let s = setup(&e);

    assert!(s.fee_forwarder.has_role(&s.manager, &Symbol::new(&e, "manager")).is_some());
    assert!(s.fee_forwarder.has_role(&s.relayer, &Symbol::new(&e, "executor")).is_some());
    assert_eq!(s.fee_forwarder.get_admin(), Some(s.admin.clone()));
}

// ── call stack depth & cross-contract invocation chain validation ────────────

/// Mock verifier contract that validates an authentication proof/payload.
#[contract]
pub struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn verify(_e: Env, payload: Val, proof: Val) -> bool {
        let _ = (payload, proof);
        // Validates successfully without exceeding host resource limits
        true
    }
}

/// Mock policy contract that invokes an external verifier to validate policy conditions.
#[contract]
pub struct MockPolicy;

#[contractimpl]
impl MockPolicy {
    pub fn enforce_with_verifier(e: Env, verifier: Address, payload: Val, proof: Val) -> bool {
        let verifier_client = MockVerifierClient::new(&e, &verifier);
        verifier_client.verify(&payload, &proof)
    }
}

/// Mock smart account contract that intercepts forwarded calls and evaluates
/// an attached policy before dispatching.
#[contract]
pub struct MockAccount;

#[contractimpl]
impl MockAccount {
    pub fn execute_with_policy(
        e: Env,
        policy: Address,
        verifier: Address,
        payload: Val,
        proof: Val,
    ) -> bool {
        let policy_client = MockPolicyClient::new(&e, &policy);
        policy_client.enforce_with_verifier(&verifier, &payload, &proof)
    }
}

/// Proxy contract to simulate deep non-reentrant cross-contract call chains.
#[contract]
pub struct RecursiveProxy;

#[contractimpl]
impl RecursiveProxy {
    pub fn recurse_and_call(
        e: Env,
        chain: Vec<Address>,
        target_account: Address,
        policy: Address,
        verifier: Address,
        payload: Val,
        proof: Val,
    ) -> bool {
        if let Some(next_proxy) = chain.get(0) {
            let mut rest = Vec::new(&e);
            for i in 1..chain.len() {
                rest.push_back(chain.get(i).unwrap());
            }
            let proxy_client = RecursiveProxyClient::new(&e, &next_proxy);
            proxy_client.recurse_and_call(
                &rest,
                &target_account,
                &policy,
                &verifier,
                &payload,
                &proof,
            )
        } else {
            let account_client = MockAccountClient::new(&e, &target_account);
            account_client.execute_with_policy(&policy, &verifier, &payload, &proof)
        }
    }
}

#[test]
fn test_account_forwarder_policy_verifier_invocation_chain() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Deploy verifier, policy, and account contracts
    let verifier_id = e.register(MockVerifier, ());
    let policy_id = e.register(MockPolicy, ());
    let account_id = e.register(MockAccount, ());

    let dummy_payload = 42u32.into_val(&e);
    let dummy_proof = 99u32.into_val(&e);

    let target_args: Vec<Val> = vec![
        &e,
        policy_id.to_val(),
        verifier_id.to_val(),
        dummy_payload,
        dummy_proof,
    ];

    let current_ledger = e.ledger().sequence();

    // Call stack depth of the chain:
    // Test runner -> FeeForwarder.forward -> MockAccount.execute_with_policy -> MockPolicy.enforce_with_verifier -> MockVerifier.verify
    let result = s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &account_id,
        &Symbol::new(&e, "execute_with_policy"),
        &target_args,
        &s.user,
        &s.relayer,
    );

    let bool_res: bool = bool::try_from_val(&e, &result).unwrap();
    assert!(bool_res);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), s.fee_amount);
}

#[test]
fn test_invocation_chain_under_maximum_call_stack_depth() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let verifier_id = e.register(MockVerifier, ());
    let policy_id = e.register(MockPolicy, ());
    let account_id = e.register(MockAccount, ());
    let proxy_id = e.register(RecursiveProxy, ());

    let dummy_payload = 123u32.into_val(&e);
    let dummy_proof = 456u32.into_val(&e);

    // Build a chain of distinct proxy contracts (Soroban disallows same-contract
    // re-entrancy) safely within Soroban's maximum host call stack depth limit.
    let mut chain = Vec::new(&e);
    for _ in 0..10 {
        chain.push_back(e.register(RecursiveProxy, ()));
    }

    let target_args: Vec<Val> = vec![
        &e,
        chain.into_val(&e),
        account_id.to_val(),
        policy_id.to_val(),
        verifier_id.to_val(),
        dummy_payload,
        dummy_proof,
    ];

    let current_ledger = e.ledger().sequence();

    let result = s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &proxy_id,
        &Symbol::new(&e, "recurse_and_call"),
        &target_args,
        &s.user,
        &s.relayer,
    );

    let bool_res: bool = bool::try_from_val(&e, &result).unwrap();
    assert!(bool_res);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), s.fee_amount);
}

#[test]
#[should_panic]
fn test_invocation_chain_exceeding_maximum_call_stack_depth_fails_safely() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let verifier_id = e.register(MockVerifier, ());
    let policy_id = e.register(MockPolicy, ());
    let account_id = e.register(MockAccount, ());
    let proxy_id = e.register(RecursiveProxy, ());

    let dummy_payload = 123u32.into_val(&e);
    let dummy_proof = 456u32.into_val(&e);

    // Passing proxy_id inside its own chain triggers Soroban's re-entrancy/depth failure.
    let chain = vec![&e, proxy_id.clone()];

    let target_args: Vec<Val> = vec![
        &e,
        chain.into_val(&e),
        account_id.to_val(),
        policy_id.to_val(),
        verifier_id.to_val(),
        dummy_payload,
        dummy_proof,
    ];

    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &proxy_id,
        &Symbol::new(&e, "recurse_and_call"),
        &target_args,
        &s.user,
        &s.relayer,
    );
}

// ── fee cap: MAX_FEE_CAP enforcement ────────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn forward_rejects_fee_exceeding_cap() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Lower the cap to below the default fee_amount used in setup.
    s.fee_forwarder.set_fee_cap(&(s.fee_amount - 1), &s.manager);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
fn forward_accepts_fee_exactly_at_cap() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Set cap exactly equal to fee_amount — boundary should be accepted.
    s.fee_forwarder.set_fee_cap(&s.fee_amount, &s.manager);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Should not panic.
    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
fn set_fee_cap_by_manager_updates_cap() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_cap: i128 = 500_000;
    s.fee_forwarder.set_fee_cap(&new_cap, &s.manager);
    assert_eq!(s.fee_forwarder.get_fee_cap(), new_cap);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn set_fee_cap_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.set_fee_cap(&500_000, &not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn set_fee_cap_rejects_zero() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.set_fee_cap(&0, &s.manager);
}

#[test]
fn constructor_sets_default_fee_cap() {
    let e = Env::default();
    let s = setup(&e);

    use super::DEFAULT_FEE_CAP;
    assert_eq!(s.fee_forwarder.get_fee_cap(), DEFAULT_FEE_CAP);
}

// ── adversarial test suite: compromised relayer simulation ───────────────────
//
// Simulates malicious modifications to parameters in `forward` (sponsored execution)
// by an adversarial / compromised relayer attempting to:
//   - Steal user funds (excessive fee, negative/zero fee, redirecting fees, changing fee token)
//   - Modify calldata (target contract, target function, target arguments)
//   - Bypass authorization (substituting user, executing expired authorization,
//     unauthorized caller posing as relayer, replay/mismatched auth tree)
//
// Acceptance Criteria: All compromised requests strictly rejected.

#[test]
#[should_panic]
fn adversarial_relayer_tamper_target_contract() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // User signs authorization for legitimate target contract
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Adversarial relayer attempts to redirect invocation to a malicious target
    let malicious_target = Address::generate(&e);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            malicious_target.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &malicious_target,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_target_function() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let legitimate_fn = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // User signs for legitimate function "greet"
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &legitimate_fn, &fn_args);

    // Adversarial relayer modifies target function to "drain" or unexpected function
    let malicious_fn = Symbol::new(&e, "drain");
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            malicious_fn.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &malicious_fn,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_target_arguments() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "act_as");
    let legitimate_args: Vec<Val> = vec![&e, s.user.clone().into_val(&e)];
    let current_ledger = e.ledger().sequence();

    // User signs invocation with legitimate arguments
    let target_invoke = MockAuthInvoke {
        contract: &s.target.address,
        fn_name: "act_as",
        args: (s.user.clone(),).into_val(&e),
        sub_invokes: &[],
    };
    let user_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            legitimate_args.clone(),
        )
            .into_val(&e),
        sub_invokes: &[target_invoke],
    };

    // Adversarial relayer modifies arguments (e.g. replacing caller with attacker)
    let attacker = Address::generate(&e);
    let tampered_args: Vec<Val> = vec![&e, attacker.clone().into_val(&e)];
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            tampered_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &tampered_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_fee_token() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // User signed auth for s.token
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Relayer attempts to substitute a different, more expensive token or victim token
    let malicious_token = Address::generate(&e);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            malicious_token.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &malicious_token,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_user_address() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Relayer attempts to charge another innocent user who did not authorize this call
    let victim_user = Address::generate(&e);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            victim_user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &victim_user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_max_fee_amount() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // User signed auth with max_fee_amount = 150_000
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Relayer attempts to pass a forged higher max_fee_amount to collect exorbitant fee
    let inflated_max_fee = s.max_fee_amount * 10;
    let inflated_fee = inflated_max_fee;
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            inflated_fee,
            inflated_max_fee,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &inflated_fee,
            &inflated_max_fee,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_expiration_ledger() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let signed_ledger = e.ledger().sequence();

    // User signed auth with signed_ledger
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Relayer modifies expiration_ledger parameter
    let modified_ledger = signed_ledger + 500;
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            modified_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &modified_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic(expected = "Error(Contract, #5003)")]
fn adversarial_relayer_excessive_fee_beyond_max() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Compromised relayer attempts to extract fee > max_fee_amount
    let stolen_fee = s.max_fee_amount + 10_000;
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            stolen_fee,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &stolen_fee,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic(expected = "Error(Contract, #5003)")]
fn adversarial_relayer_zero_or_negative_fee() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let invalid_fee = 0i128;
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            invalid_fee,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &invalid_fee,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn adversarial_compromised_caller_not_holding_executor_role() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Attacker without executor role tries to execute sponsored request
    let attacker = Address::generate(&e);
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let attacker_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            attacker.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &attacker, invoke: &attacker_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &attacker,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_expired_ledger() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let past_ledger = 100u32;

    // Fast-forward current ledger past the authorization expiration ledger
    e.ledger().set_sequence_number(200u32);

    let (user_invoke, relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    // Relayer attempts to submit an expired request
    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &past_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

