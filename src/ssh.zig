const std = @import("std");
const c = @import("libssh");
const abuse = @import("abuse.zig");
const audit = @import("audit.zig");
const auth = @import("auth.zig");
const config = @import("config.zig");
const netmatch = @import("netmatch.zig");

pub fn authenticate(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    session: c.ssh_session,
    peer_ip: ?[]const u8,
) !*const config.UserConfig {
    // Two independent ceilings (PLAN §8.4):
    //
    //   HARD failures — a real credential rejection (wrong password,
    //   unknown-user password spray, a matched key whose signature is
    //   invalid, or a known user hitting the `from` allowlist). These
    //   feed the cross-session abuse suppressor and the escalating
    //   backoff, and 6 of them (OpenSSH's MaxAuthTries default) ends the
    //   session.
    //
    //   SOFT operations — method `none` and public-key *probes* (the
    //   `SSH_PUBLICKEY_STATE_NONE` "would this key work?" offers, and
    //   offers of keys that aren't configured). A stock client sends
    //   `none` plus one probe per agent key BEFORE it ever tries a
    //   password, so counting these as hard failures made a normal
    //   5-key agent trip the 6-attempt ceiling and the legitimate
    //   partner's own IP suppression. Soft ops get no backoff and never
    //   touch the abuse table; they only have a generous ceiling so a
    //   client cannot pin a session forever by looping probes (the
    //   `.offered` path resets libssh's idle timer each round).
    const max_hard_failures: u32 = 6;
    const max_soft_ops: u32 = 64;
    var hard_failures: u32 = 0;
    var soft_ops: u32 = 0;
    const ip_str = peer_ip orelse "";

    while (true) {
        const msg = c.ssh_message_get(session) orelse return error.LibsshFailure;
        defer c.ssh_message_free(msg);

        if (c.ssh_message_type(msg) != c.SSH_REQUEST_AUTH) {
            _ = c.ssh_message_reply_default(msg);
            continue;
        }

        const subtype: c_uint = @intCast(c.ssh_message_subtype(msg));

        // v0.7.1: read username early so the failure-path methods
        // bitmask can be narrowed per-user. The username accessor is
        // safe here because the `ssh_message_type` check above
        // already filtered out non-auth messages — every codepath
        // reaching this point holds a `SSH_REQUEST_AUTH` message,
        // including `none`/`password`/`publickey` subtypes (all of
        // which carry a username).
        //
        // Anti-enumeration trade-off (see `methodsForUser` for the
        // matrix): only password-only known users get a narrowed
        // response. The unknown-user response shape is unchanged
        // from v0.7.0 (`PASSWORD|PUBLICKEY`), so probing for valid
        // usernames via the methods list still has to confront the
        // ambiguity between "unknown user" and "known user with
        // password+keys" / "known user with keys only". A
        // password-only known user IS intentionally distinguishable
        // from those — that's the cost of the noise reduction, and
        // it's the right cost for the partner-deploy threat model
        // where partner usernames are pre-shared anyway.
        const username_ptr = c.ssh_message_auth_user(msg);
        const username_for_methods: ?[]const u8 = if (username_ptr != null)
            std.mem.span(username_ptr)
        else
            null;

        // `is_hard` classifies this message's failure for the ceilings
        // above. Default `false` (soft): method `none` and any
        // unrecognized auth method fall through as soft.
        var is_hard = false;

        if (subtype == c.SSH_AUTH_METHOD_PASSWORD) {
            const password_ptr = c.ssh_message_auth_password(msg);
            if (username_ptr != null and password_ptr != null) {
                const username = std.mem.span(username_ptr);
                const password = std.mem.span(password_ptr);
                // Any actual password attempt is a hard failure if it
                // doesn't succeed — that's exactly the password-spray
                // pressure the abuse layer exists to throttle.
                if (cfg.findUser(username)) |user| {
                    if (!netmatch.allowed(user.from, ip_str)) {
                        // Run the same argon2id dummy work a real verify
                        // would, so a source outside the `from` allowlist
                        // cannot enumerate valid usernames by timing the
                        // ~0 ms early reject against the ~58 ms KDF path.
                        auth.runDummyVerify(io, allocator, password);
                        audit.log(io, username, "auth.password", null, .denied, "source not allowed", ip_str);
                        is_hard = true;
                    } else if (auth.verifyPassword(io, allocator, user, password)) {
                        _ = c.ssh_message_auth_reply_success(msg, 0);
                        audit.log(io, username, "auth.password", null, .ok, "", ip_str);
                        abuse.recordSuccess(io, ip_str);
                        return user;
                    } else {
                        audit.log(io, username, "auth.password", null, .denied, "bad password", ip_str);
                        is_hard = true;
                    }
                } else {
                    _ = auth.verifyLogin(io, allocator, cfg, username, password);
                    audit.log(io, username, "auth.password", null, .denied, "unknown user", ip_str);
                    is_hard = true;
                }
            }
        } else if (subtype == c.SSH_AUTH_METHOD_PUBLICKEY) {
            const decision = handlePublicKeyMessage(io, allocator, cfg, msg, peer_ip);
            switch (decision) {
                .accepted => |user| {
                    abuse.recordSuccess(io, ip_str);
                    return user;
                },
                .offered => {
                    // A probe ("would this key work?"). `pk_ok` was
                    // already sent; wait for the signed follow-up. Bound
                    // the number of probes so a client cannot pin the
                    // session by looping offers forever.
                    soft_ops += 1;
                    if (soft_ops >= max_soft_ops) {
                        audit.log(io, null, "auth.too_many_attempts", null, .denied, "pubkey probes", ip_str);
                        return error.LibsshFailure;
                    }
                    continue;
                },
                // A matched key with an invalid signature (or a `from`
                // rejection) is a real failure; an unknown user / no
                // keys / unconfigured-key offer is a soft probe.
                .hard_denied => is_hard = true,
                .soft_denied => {},
            }
        }

        if (is_hard) {
            // Real credential rejection: feed the abuse suppressor,
            // apply escalating backoff, disconnect at the ceiling.
            hard_failures += 1;
            abuse.recordFailure(io, ip_str, audit.nowMonotonicMs());
            const delay_ms = @min(hard_failures * 250, 2000);
            std.Io.sleep(io, .fromMilliseconds(delay_ms), .awake) catch {};
            if (hard_failures >= max_hard_failures) {
                audit.log(io, null, "auth.too_many_attempts", null, .denied, "", ip_str);
                return error.LibsshFailure;
            }
        } else {
            // Soft op (`none`, unrecognized method, soft pubkey probe):
            // no backoff, no abuse credit, just a loop bound.
            soft_ops += 1;
            if (soft_ops >= max_soft_ops) {
                audit.log(io, null, "auth.too_many_attempts", null, .denied, "probes", ip_str);
                return error.LibsshFailure;
            }
        }

        _ = c.ssh_message_auth_set_methods(msg, methodsForUser(cfg, username_for_methods));
        _ = c.ssh_message_reply_default(msg);
    }
}

/// Compute the auth-methods bitmask sent in `userauth_failure` to
/// the client for `username`. Modern SSH clients use this list to
/// decide which methods to keep trying — when the server says
/// `PASSWORD` only, well-behaved clients stop offering keys.
///
/// Trade-off vs PLAN §8.4 anti-enumeration: full anti-enumeration
/// would require an indistinguishable response shape across "valid
/// user with X auth" and "unknown user." This patch sacrifices
/// some of that — a password-only known user gets a narrower
/// methods bitmask than the unknown-user response, so an attacker
/// who probes can distinguish "exists with password-only" from
/// "unknown OR exists with password+keys OR exists with keys
/// only." The narrowing matrix:
///
///   - User exists with both password AND keys → `PASSWORD|PUBLICKEY`
///     (= unknown-user default; no leak, no narrowing benefit).
///   - User exists with password only           → `PASSWORD` (narrowed).
///     INTENTIONALLY distinguishable from the unknown-user default —
///     leaks "this username exists with password-only auth." For
///     the partner-deploy threat model where partner usernames are
///     known to the partner anyway, and the operational pain of
///     the wider bitmask is real (clients try every key in the
///     agent before the password prompt, drowning the audit log),
///     that leak is the right trade.
///     Operators with a stricter posture configure both methods on
///     every user so the response stays at the default.
///   - User exists with keys only               → `PASSWORD|PUBLICKEY`
///     (no narrowing; matches unknown-user default — the rarer
///     key-only case stays anti-enumeration safe).
///   - User unknown                              → `PASSWORD|PUBLICKEY`.
fn methodsForUser(cfg: config.Config, username: ?[]const u8) c_int {
    const both: c_int = @intCast(c.SSH_AUTH_METHOD_PASSWORD | c.SSH_AUTH_METHOD_PUBLICKEY);
    const name = username orelse return both;
    const user = cfg.findUser(name) orelse return both;
    if (user.password_hash != null and user.keys.len == 0) {
        return @intCast(c.SSH_AUTH_METHOD_PASSWORD);
    }
    return both;
}

const PublicKeyDecision = union(enum) {
    /// Signature verified and the key matches a configured key for the user.
    /// Reply success was already sent; caller should return this user.
    accepted: *const config.UserConfig,
    /// Client offered an acceptable key (no signature yet). `pk_ok` was
    /// already sent; caller should continue the loop and wait for the
    /// follow-up signed message.
    offered,
    /// A real credential rejection: a key that matched a configured key
    /// but whose signature failed to verify, or a known user rejected
    /// by the `from` allowlist. Counts as a hard failure (abuse +
    /// backoff).
    hard_denied,
    /// A probe that reveals nothing usable: unknown user, no keys
    /// configured, an offer of a key that isn't configured, or a
    /// malformed offer. Does NOT count against the abuse suppressor —
    /// stock clients enumerate agent keys this way on every login.
    soft_denied,
};

fn handlePublicKeyMessage(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: config.Config,
    msg: c.ssh_message,
    peer_ip: ?[]const u8,
) PublicKeyDecision {
    const username_ptr = c.ssh_message_auth_user(msg);
    if (username_ptr == null) return .soft_denied;
    const username = std.mem.span(username_ptr);

    const ip_str = peer_ip orelse "";

    const presented = c.ssh_message_auth_pubkey(msg);
    if (presented == null) {
        audit.log(io, username, "auth.publickey", null, .denied, "no key in message", ip_str);
        return .soft_denied;
    }

    const user = cfg.findUser(username) orelse {
        // Unknown user. Run dummy key-import + compare so the timing
        // matches what a known-user-but-wrong-key attempt would take.
        // Without this, an attacker can probe valid usernames by
        // measuring the response time difference. PLAN §8.4: failed
        // authentication does not reveal whether the username exists.
        _ = matchAgainstDummyKey(allocator, presented);
        audit.log(io, username, "auth.publickey", null, .denied, "unknown user", ip_str);
        return .soft_denied;
    };

    if (!netmatch.allowed(user.from, ip_str)) {
        _ = matchAgainstDummyKey(allocator, presented);
        audit.log(io, username, "auth.publickey", null, .denied, "source not allowed", ip_str);
        return .hard_denied;
    }

    if (user.keys.len == 0) {
        // Known user, password-only. Same dummy work so the timing
        // discriminator (does this user accept keys?) is also masked.
        _ = matchAgainstDummyKey(allocator, presented);
        audit.log(io, username, "auth.publickey", null, .denied, "no keys configured", ip_str);
        return .soft_denied;
    }

    const matched_idx = matchesAnyConfiguredKey(allocator, user, presented) orelse {
        audit.log(io, username, "auth.publickey", null, .denied, "key not configured", ip_str);
        return .soft_denied;
    };

    const state = c.ssh_message_auth_publickey_state(msg);
    switch (state) {
        c.SSH_PUBLICKEY_STATE_NONE => {
            // Client is asking "would this key work?". Answer yes; libssh
            // will then receive a signed follow-up that comes back with
            // SSH_PUBLICKEY_STATE_VALID after libssh verifies the signature.
            if (c.ssh_message_auth_reply_pk_ok_simple(msg) != c.SSH_OK) {
                audit.log(io, username, "auth.publickey", null, .failed, "pk_ok reply failed", ip_str);
                return .soft_denied;
            }
            return .offered;
        },
        c.SSH_PUBLICKEY_STATE_VALID => {
            _ = c.ssh_message_auth_reply_success(msg, 0);
            // Audit the algorithm of the *matched* key, not always
            // keys[0]: a user with multiple configured keys would
            // otherwise look like every login used the first key.
            audit.log(io, username, "auth.publickey", null, .ok, user.keys[matched_idx].algorithm, ip_str);
            return .{ .accepted = user };
        },
        else => {
            // SSH_PUBLICKEY_STATE_WRONG, SSH_PUBLICKEY_STATE_ERROR, anything else.
            audit.log(io, username, "auth.publickey", null, .denied, "signature invalid", ip_str);
            return .hard_denied;
        },
    }
}

/// Return the index of the first configured key that matches the
/// presented key, or `null` if none match. Returning the index lets
/// the audit log identify which configured key the client used —
/// `user.keys[0]` would lie for users with multiple keys.
fn matchesAnyConfiguredKey(
    allocator: std.mem.Allocator,
    user: *const config.UserConfig,
    presented: c.ssh_key,
) ?usize {
    if (user.keys.len == 0) return null;
    const presented_type = c.ssh_key_type(presented);

    for (user.keys, 0..) |configured, i| {
        // Per-attempt scratch dupes go through the session's allocator
        // (PLAN §5: no global allocator). Lifetime is one loop iteration;
        // each `defer free` runs before the next attempt. A future
        // optimization may cache the parsed `ssh_key` per session to
        // skip the import on repeat lookups (see SECURITY-AUDIT.md).
        const algo_z = allocator.dupeZ(u8, configured.algorithm) catch return null;
        defer allocator.free(algo_z);
        const blob_z = allocator.dupeZ(u8, configured.blob) catch return null;
        defer allocator.free(blob_z);

        const want_type = c.ssh_key_type_from_name(algo_z.ptr);
        if (want_type != presented_type) continue;

        var parsed: c.ssh_key = null;
        const rc = c.ssh_pki_import_pubkey_base64(blob_z.ptr, want_type, &parsed);
        if (rc != c.SSH_OK or parsed == null) continue;
        defer c.ssh_key_free(parsed);

        if (c.ssh_key_cmp(presented, parsed, c.SSH_KEY_CMP_PUBLIC) == 0) {
            return i;
        }
    }
    return null;
}

/// Hardcoded dummy Ed25519 public-key blob (an existing public key —
/// the matching private key is intentionally not stored anywhere; we
/// only ever compare against this, never accept a signature from it).
/// Used to give unknown-user / no-keys-configured pubkey attempts the
/// same import-and-compare timing as a real lookup, so an attacker
/// cannot probe valid usernames by measuring response time. PLAN §8.4.
const dummy_pubkey_algorithm = "ssh-ed25519";
const dummy_pubkey_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIIH9hN3OvKbo/u+wsxJjPXpOAFn4mP+/p1bbyT2bF50K";

/// Run the same import-and-compare work matchesAnyConfiguredKey does
/// for a real configured key, but against a dummy that will never
/// match. Always returns `false`. The point is the *cost* — masking
/// the timing channel between "this user exists / has keys" and "this
/// user does not."
fn matchAgainstDummyKey(allocator: std.mem.Allocator, presented: c.ssh_key) bool {
    // Same allocator path `matchesAnyConfiguredKey` uses (PLAN §5).
    // Symmetry matters: any caching added there must also be added
    // here, or known-user vs unknown-user paths develop a measurable
    // timing difference that re-opens the username-enumeration channel
    // PLAN §8.4 closed via the dummy-import cost.
    const algo_z = allocator.dupeZ(u8, dummy_pubkey_algorithm) catch return false;
    defer allocator.free(algo_z);
    const blob_z = allocator.dupeZ(u8, dummy_pubkey_blob) catch return false;
    defer allocator.free(blob_z);

    const want_type = c.ssh_key_type_from_name(algo_z.ptr);
    var parsed: c.ssh_key = null;
    const rc = c.ssh_pki_import_pubkey_base64(blob_z.ptr, want_type, &parsed);
    if (rc != c.SSH_OK or parsed == null) return false;
    defer c.ssh_key_free(parsed);

    _ = c.ssh_key_cmp(presented, parsed, c.SSH_KEY_CMP_PUBLIC);
    return false;
}

