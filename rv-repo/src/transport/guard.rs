//! The redirect policy and the address screen that keep repository requests
//! off networks the user did not name.

use std::collections::HashSet;
use std::error::Error as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use rv_config::{Config, redact_url};
use url::Url;

use crate::error::{RedirectRejectionKind, Result};
use crate::proxy::ProxySet;

#[derive(Debug, Clone, thiserror::Error)]
#[error("{kind}: {details}")]
pub(super) struct RedirectPolicyError {
    pub(super) kind: RedirectRejectionKind,
    pub(super) details: String,
}

fn reject(
    kind: RedirectRejectionKind,
    details: String,
) -> std::result::Result<(), RedirectPolicyError> {
    Err(RedirectPolicyError { kind, details })
}

/// The address an IP-literal host names. Literals never reach a resolver,
/// so the screens check these themselves.
pub(super) fn ip_literal(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        url::Host::Ipv4(addr) => Some(IpAddr::V4(addr)),
        url::Host::Ipv6(addr) => Some(IpAddr::V6(addr)),
        url::Host::Domain(_) => None,
    }
}

pub(super) fn origin_key(url: &Url) -> Option<String> {
    matches!(url.scheme(), "http" | "https").then(|| url.origin().ascii_serialization())
}

/// A set of hostnames allowed to sit on a non-global address, in whichever of
/// the two shapes the reader needs.
///
/// The distinction is the whole point of the split, so it is a type and not a
/// convention: [`ConfiguredHosts`] cannot change after the client is built,
/// [`TrustedHosts`] can. Anything screening a redirect reads the first kind.
pub(super) trait ExemptHosts: Send + Sync + 'static {
    fn contains(&self, host: &str) -> bool;
}

/// Hostnames fixed when the client is built, such as the hosts of the
/// configured proxies.
///
/// Read by [`RedirectGuard`] and by the redirect-capable client's
/// [`GlobalOnlyResolver`], which is why it is immutable: those two read it at
/// different moments (policy evaluation, then connect), and a set that could
/// grow in between would let a trust grant taken by an unrelated concurrent
/// task retroactively excuse a redirect the policy only permitted because the
/// resolver was going to screen it.
#[derive(Debug, Default, Clone)]
pub(super) struct ConfiguredHosts(pub(super) Arc<HashSet<String>>);

impl ConfiguredHosts {
    /// Normalising on the way in is what keeps a configured `[fd00::1]` and a
    /// DNS name `fd00::1` from becoming two spellings of one host.
    pub(super) fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        Self(Arc::new(
            hosts
                .into_iter()
                .map(|host| normalized_host(&host))
                .collect(),
        ))
    }

    /// A fresh mutable set seeded with these hosts, for the runtime client.
    /// Deliberately a copy rather than a shared handle: growing it must not
    /// reach anything that screens redirects.
    pub(super) fn to_runtime_set(&self) -> TrustedHosts {
        TrustedHosts(SharedSet::new(self.0.iter().cloned()))
    }
}

impl ExemptHosts for ConfiguredHosts {
    fn contains(&self, host: &str) -> bool {
        self.0.contains(&normalized_host(host))
    }
}

/// Hostnames the runtime client may dial off the public internet: the
/// configured ones plus every repository trusted after construction.
///
/// Mutable because trust is not fully known when the client is built. The root
/// POM's `<repositories>`, and any transitive repository the user's policy
/// approves, are granted trust part-way through a resolve; a set frozen at
/// construction left every request to such a repository failing the address
/// screen the moment its name resolved onto RFC1918, which is the normal shape
/// of an on-prem registry declared in the project's own POM.
///
/// Exactly one thing reads it: the DNS resolver of the client that follows
/// same-origin redirects only ([`super::ClientSet::client_for`]). Growing it
/// therefore widens nothing but the address screen on connections `raeva` was
/// already told to make, and no redirect decision anywhere depends on when it
/// grew.
#[derive(Debug, Default, Clone)]
pub(super) struct TrustedHosts(SharedSet);

impl TrustedHosts {
    /// Add one host. Idempotent, and normalising on the way in is what keeps a
    /// configured `[fd00::1]` and a runtime `fd00::1` from becoming two
    /// spellings of one host.
    pub(super) fn insert(&self, host: &str) {
        self.0.insert(normalized_host(host));
    }
}

impl ExemptHosts for TrustedHosts {
    fn contains(&self, host: &str) -> bool {
        self.0.contains(&normalized_host(host))
    }
}

/// The origins (scheme, host and port, as [`origin_key`] writes them) that
/// may sit on a non-global address: the configured ones plus every
/// repository trusted after construction.
///
/// This is what decides which client a request uses, and so whether a
/// resolver that waves its host through ever sees it. A resolver only knows
/// a name, so the host sets above cannot tell `nexus.corp:8081` from
/// `nexus.corp:6379`; this set can.
pub(super) type TrustedOrigins = SharedSet;

#[derive(Debug, Default, Clone)]
pub(super) struct SharedSet(Arc<RwLock<HashSet<String>>>);

impl SharedSet {
    pub(super) fn new(items: impl IntoIterator<Item = String>) -> Self {
        Self(Arc::new(RwLock::new(items.into_iter().collect())))
    }

    pub(super) fn insert(&self, item: String) {
        self.0
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .insert(item);
    }

    pub(super) fn contains(&self, item: &str) -> bool {
        self.0
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .contains(item)
    }
}

/// Everything the SSRF guards derive from the user's configuration, in the
/// three shapes they consume it.
///
/// `origins` (scheme + host + port) is the authority a redirect can be granted:
/// it gates both which origin may issue a cross-origin redirect and which
/// non-global or proxied target may be followed. It is fixed at construction
/// from `raeva.toml` alone. Root issuers enter `root_issuer`, without target
/// exemptions. A root declaration cannot authorize a mirror redirect to its
/// private host.
///
/// `exempt_hosts` is bare hostnames, because a resolver only ever sees a name,
/// never a port. It is consumed by the redirect-capable client's
/// [`GlobalOnlyResolver`] and, for the one rejection below that depends on
/// knowing the resolver will stand down, by [`RedirectGuard::screen_target`].
/// It is deliberately *wider* than `origins`: it also carries configured proxy
/// hosts, so a corporate proxy at `proxy.corp` on an RFC1918 address stays
/// connectable. A merely exempt host must never turn into a redirect target the
/// user did not name, which is why the policy consults `origins` and never this
/// set for authorisation.
///
/// `proxies` uses the client's proxy selection for each redirect target,
/// including scheme selection and `non_proxy_hosts`. Only a target carried
/// by a proxy needs the configured-origin restriction; direct targets still
/// pass through the DNS address screen.
///
/// Each HTTP client fixes these fields at construction, including root clients. The policy
/// and the resolver read `exempt_hosts` at different moments, so a redirect
/// target that was not exempt at policy-evaluation time must be DNS-screened at
/// connect time, regardless of concurrent trust grants. Runtime trust lives in
/// a separate [`TrustedHosts`] set belonging to a separate, same-origin-only
/// client, so no grant can land in that window.
#[derive(Debug, Default, Clone)]
pub(super) struct RedirectGuard {
    pub(super) origins: HashSet<String>,
    /// Additional issuer only; never a redirect-target exemption.
    pub(super) root_issuer: Option<String>,
    pub(super) exempt_hosts: ConfiguredHosts,
    pub(super) proxies: ProxySet,
}

/// Collect the repository, mirror and proxy endpoints the guards screen against.
pub(super) fn redirect_guard(config: &Config, proxies: &ProxySet) -> Result<RedirectGuard> {
    let mut origins = HashSet::new();
    let mut exempt_hosts: Vec<String> = config.proxies().iter().map(|p| p.host.clone()).collect();
    let repositories = config
        .repositories()
        .iter()
        .map(|repository| &repository.url);
    for configured_url in repositories.chain(config.mirrors().iter().map(|mirror| &mirror.url)) {
        let url = Url::parse(configured_url)?;
        if let Some(origin) = origin_key(&url) {
            origins.insert(origin);
            exempt_hosts.extend(url.host_str().map(str::to_string));
        }
    }
    Ok(RedirectGuard {
        origins,
        root_issuer: None,
        exempt_hosts: ConfiguredHosts::new(exempt_hosts),
        proxies: proxies.clone(),
    })
}

/// Normalise a configured host for comparison against a DNS name. Bracketed
/// IPv6 literals never reach a resolver, but stripping the brackets keeps the
/// set free of two spellings of one host.
pub(super) fn normalized_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

/// Longest redirect chain followed before the request is abandoned.
pub(super) const MAX_REDIRECT_HOPS: usize = 5;

/// Follow same-origin redirects plus one explicitly trusted cross-origin hop.
///
/// The issuer of the cross-origin redirect must be a repository or mirror
/// origin present when the client was built, or its root-model issuer.
/// Both sides of that hop must use
/// HTTPS, and any later redirect must stay on the new origin. The chain is
/// capped at [`MAX_REDIRECT_HOPS`] redirects.
///
/// The cross-origin target must also be a public-internet address, established
/// by one of three screens depending on what `raeva` can know at redirect time:
///
/// * An IP literal carries its address, so it is screened here.
/// * A hostname normally carries none, so it is screened by
///   [`GlobalOnlyResolver`] at connect time, which is also what closes the
///   check-then-use window a policy-side resolution would open.
/// * A hostname is screened *here* instead whenever the resolver could not do
///   it: when a proxy carries the target its name is resolved by the proxy
///   and never reaches the resolver, and when the host sits in the exempt set
///   the resolver waves it through by design.
///
/// Non-global targets are allowed only when the target origin (scheme, host
/// *and port*) is itself a configured repository or mirror, so pointing `raeva`
/// at an on-prem registry stays a decision the user makes in `raeva.toml`. Host-level
/// trust is not enough: configuring `https://nexus.corp` must not license a
/// redirect to `https://nexus.corp:8443`, which is a different service on the
/// same private machine.
///
/// The proxy case is the strictest, because a proxy dissolves the distinction
/// between public and private that every other screen rests on: `raeva` hands the
/// proxy a name and the proxy resolves and connects on its behalf, so
/// `https://admin.internal/` becomes an internal connection made by a host that
/// can reach it. A proxied cross-origin redirect to a hostname is therefore
/// followed only to a configured origin. Users behind a proxy whose repository
/// redirects to a CDN must name that CDN origin in their configuration.
///
/// reqwest's default policy follows redirects to any origin, which would let a
/// hostile mirror bounce a fetch to `http://attacker/` and bypass both
/// `Repository::url_for_path`'s origin check and TLS, or aim it at
/// `https://169.254.169.254/` and turn `raeva` into an SSRF probe for the private
/// network it runs on.
pub(super) fn trusted_redirect_policy(guard: RedirectGuard) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        match guard.evaluate(attempt.previous(), attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(rejection) => attempt.error(rejection),
        }
    })
}

impl RedirectGuard {
    /// Decide a single redirect hop. Split out of the policy closure so each
    /// branch is unit-testable without staging a server per case.
    pub(super) fn evaluate(
        &self,
        previous: &[Url],
        target: &Url,
    ) -> std::result::Result<(), RedirectPolicyError> {
        use RedirectRejectionKind as Kind;
        if previous.len() >= MAX_REDIRECT_HOPS {
            return reject(
                Kind::ChainLimit,
                format!(
                    "redirect chain reached {MAX_REDIRECT_HOPS} hops before {}",
                    redact_url(target)
                ),
            );
        }
        let Some(issuer) = previous.last() else {
            return reject(
                Kind::OriginNotConfigured,
                format!(
                    "redirect to {} has no issuing request origin",
                    redact_url(target)
                ),
            );
        };
        if issuer.origin() == target.origin() {
            return Ok(());
        }
        if previous
            .windows(2)
            .any(|pair| pair[0].origin() != pair[1].origin())
        {
            return reject(
                Kind::SecondCrossOriginHop,
                format!(
                    "redirect chain already crossed origin once; refusing {} -> {}",
                    issuer.origin().ascii_serialization(),
                    redact_url(target)
                ),
            );
        }
        let issuer_origin = issuer.origin().ascii_serialization();
        if !self.origins.contains(&issuer_origin)
            && self.root_issuer.as_ref() != Some(&issuer_origin)
        {
            return reject(
                Kind::OriginNotConfigured,
                format!(
                    "redirect issuer {issuer_origin} is not a configured repository, mirror or root-model repository"
                ),
            );
        }
        if issuer.scheme() != "https" {
            return reject(
                Kind::InsecureOrigin,
                format!(
                    "plain-http trusted origin {issuer_origin} may redirect only within its own \
                     origin, not to {}; configure the repository or a mirror with the URL it \
                     redirects to",
                    redact_url(target)
                ),
            );
        }
        if target.scheme() != "https" {
            return reject(
                Kind::HttpsDowngrade,
                format!(
                    "redirect from {issuer_origin} to {} would downgrade transport",
                    redact_url(target)
                ),
            );
        }
        self.screen_target(target, &issuer_origin)
    }

    /// Screen the address the cross-origin target names, or the authority that
    /// will resolve it on `raeva`'s behalf.
    pub(super) fn screen_target(
        &self,
        target: &Url,
        issuer_origin: &str,
    ) -> std::result::Result<(), RedirectPolicyError> {
        let Some(host) = target.host() else {
            return reject(
                RedirectRejectionKind::NonGlobalTarget,
                format!("redirect target {} has no host", redact_url(target)),
            );
        };
        let url::Host::Domain(domain) = host else {
            return match non_global_literal_target(target, &self.origins) {
                Some(details) => reject(RedirectRejectionKind::NonGlobalTarget, details),
                None => Ok(()),
            };
        };
        if self
            .origins
            .contains(&target.origin().ascii_serialization())
        {
            return Ok(());
        }
        if self.proxies.carries(target) {
            return reject(
                RedirectRejectionKind::ProxiedTargetNotConfigured,
                format!(
                    "a proxy would resolve and connect to {} on raeva's behalf, so {issuer_origin} \
                     may redirect only to a configured repository or mirror origin",
                    redact_url(target)
                ),
            );
        }
        // This client's resolver waves an exempt host through, so this is the
        // only screen left standing between a hostile mirror and an
        // unconfigured port on that private host. The set is frozen, so what is
        // decided here is what the resolver will see: a redirect target that was
        // not exempt at policy-evaluation time must be DNS-screened at connect
        // time, regardless of concurrent trust grants.
        if self.exempt_hosts.contains(domain) {
            return reject(
                RedirectRejectionKind::ExemptHostOriginMismatch,
                format!(
                    "{domain} is exempt from the address screen because it is configured, but \
                     {} is not a configured origin",
                    redact_url(target)
                ),
            );
        }
        // Nothing exempts this name, so the resolver screens its addresses when
        // the connection is made.
        Ok(())
    }
}

/// Reject a cross-origin target whose host is an IP literal outside the public
/// internet. Hostname targets carry no address at this point and are screened
/// by [`GlobalOnlyResolver`] instead.
pub(super) fn non_global_literal_target(
    target: &Url,
    trusted_origins: &HashSet<String>,
) -> Option<String> {
    let addr = ip_literal(target)?;
    if is_globally_routable(addr)
        || trusted_origins.contains(&target.origin().ascii_serialization())
    {
        return None;
    }
    Some(format!(
        "redirect target {} resolves to non-global address {addr}",
        redact_url(target)
    ))
}

/// DNS resolver that refuses any name resolving outside the public internet.
///
/// Screening here rather than in the redirect policy is what closes the
/// check-then-use window: hyper connects to exactly the addresses returned
/// below, so a name cannot answer with a public address for the check and a
/// private one for the connection. IP literals never reach a resolver, which is
/// why [`non_global_literal_target`] screens those separately.
///
/// A request routed through a configured proxy resolves at the proxy, so only
/// the proxy host passes through here. That is why the proxy host itself is
/// exempt (it is trusted by configuration and routinely private) and why
/// [`RedirectGuard::screen_target`] takes over the target screening whenever a
/// proxy carries the target.
pub(super) struct GlobalOnlyResolver<E: ExemptHosts> {
    /// Hosts allowed to sit on a non-global address because the user named
    /// them, whether in `raeva.toml` or in the project's own POM: an on-prem
    /// registry at `nexus.corp.internal` or a proxy at `proxy.corp` is a
    /// deliberate choice, not an SSRF target.
    ///
    /// Which kind of set this is decides what the client owning this resolver
    /// may do. [`ConfiguredHosts`] is frozen and pairs with the redirect policy
    /// on the redirect-capable client: a target that policy passed on the
    /// expectation of being screened here still is, because nothing can join
    /// the set in between. [`TrustedHosts`] grows mid-resolve and pairs with
    /// the same-origin-only client, which follows nothing the policy had to
    /// pass judgement on.
    ///
    /// Exemption is host-level and therefore port-blind, so it cannot stand in
    /// for authorisation. A redirect to a merely-exempt host is rejected by the
    /// policy before any connection is attempted, and
    /// [`super::ClientSet::client_for`] hands a client only requests whose
    /// whole origin that client's set was built for. What reaches here is a
    /// direct request to a trusted origin, a hop the policy already matched
    /// against a full configured origin, or a connection to a proxy.
    pub(super) exempt_hosts: E,
}

impl<E: ExemptHosts> Resolve for GlobalOnlyResolver<E> {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_ascii_lowercase();
        // Read per resolution, not per client: the runtime set grows while a
        // resolve runs.
        let exempt = self.exempt_hosts.contains(&host);
        Box::pin(async move {
            let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0_u16))
                .await
                .map_err(ResolveError::from)?
                .collect();
            let screened = screen_resolved_addrs(&host, exempt, resolved)?;
            Ok(Box::new(screened.into_iter()) as Addrs)
        })
    }
}

pub(super) type ResolveError = Box<dyn std::error::Error + Send + Sync>;

/// Reject the whole answer when any address in it is non-global, rather than
/// filtering: a hostile authoritative server can return a public and a private
/// address together and let connection ordering pick the private one.
pub(super) fn screen_resolved_addrs(
    host: &str,
    exempt: bool,
    addrs: Vec<SocketAddr>,
) -> std::result::Result<Vec<SocketAddr>, RedirectPolicyError> {
    if let Some(blocked) = addrs
        .iter()
        .find(|addr| !exempt && !is_globally_routable(addr.ip()))
    {
        reject(
            RedirectRejectionKind::NonGlobalTarget,
            format!("{host} resolves to non-global address {}", blocked.ip()),
        )?;
    }
    Ok(addrs)
}

/// Whether an address is a plausible public-internet destination.
///
/// `IpAddr::is_global` is still unstable, so the non-global ranges are spelled
/// out here, following std's nightly implementation (`core::net::Ipv4Addr::
/// is_global` / `Ipv6Addr::is_global`) and the IANA special-purpose address
/// registries it is derived from. Three deliberate departures from std, all
/// erring towards rejection:
///
/// * std preserves the globally-reachable carve-outs inside otherwise-reserved
///   blocks: 192.0.0.9/32 (PCP anycast) and 192.0.0.10/32 (NAT64 discovery) in
///   192.0.0.0/24, and the PCP/TURN/AMT/AS112 addresses in 2001::/23. Each whole
///   block is excluded here instead. No Maven repository is served from one, and
///   one predicate per block is easier to audit than a predicate plus its holes.
/// * std treats 6to4 (2002::/16) and Teredo (2001::/32, inside 2001::/23) as
///   reachable. Both encode an arbitrary IPv4 address in the destination, which
///   is precisely the laundering step this screen exists to stop, so both are
///   excluded.
/// * std does not cover the 6to4 relay anycast prefix (192.88.99.0/24, whose
///   IANA entry became non-global when RFC 7526 deprecated it) or the dummy
///   prefix (100:0:0:1::/64, RFC 9780). Neither can carry a real destination,
///   and the first relays into the 6to4 addressing excluded above.
///
/// IPv4 addresses embedded in IPv6 are unwrapped first so `[::ffff:10.0.0.1]`
/// cannot smuggle an RFC1918 target past the check.
pub(super) fn is_globally_routable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => is_globally_routable_v4(addr),
        IpAddr::V6(addr) => is_globally_routable_v6(addr),
    }
}

pub(super) fn is_globally_routable_v4(addr: Ipv4Addr) -> bool {
    let [first, second, third, _] = addr.octets();
    !(addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_multicast()
        // 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
        || addr.is_documentation()
        // "This network" (0.0.0.0/8), which subsumes the unspecified address.
        || first == 0
        // IETF protocol assignments (192.0.0.0/24), carve-outs included.
        || (first == 192 && second == 0 && third == 0)
        // Deprecated 6to4 relay anycast (192.88.99.0/24).
        || (first == 192 && second == 88 && third == 99)
        // Shared address space (100.64.0.0/10), benchmarking (198.18.0.0/15)
        // and reserved (240.0.0.0/4) have no stable std predicate.
        || (first == 100 && (64..128).contains(&second))
        || (first == 198 && second & 0xfe == 18)
        || first >= 240)
}

pub(super) fn is_globally_routable_v6(addr: Ipv6Addr) -> bool {
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    if let Some(mapped) = embedded_ipv4(addr) {
        return is_globally_routable_v4(mapped);
    }
    let segments = addr.segments();
    let [first, second, third, fourth, ..] = segments;
    !(
        // Unique-local (fc00::/7) and link-local (fe80::/10).
        first & 0xfe00 == 0xfc00
        || first & 0xffc0 == 0xfe80
        // Site-local (fec0::/10). Deprecated by RFC 3879 but still routed on
        // legacy networks, and never a public destination.
        || first & 0xffc0 == 0xfec0
        // Discard-only (100::/64).
        || (first == 0x0100 && second == 0 && third == 0 && fourth == 0)
        // Dummy prefix (100:0:0:1::/64), reserved by RFC 9780 as a placeholder
        // that is never routed.
        || (first == 0x0100 && second == 0 && third == 0 && fourth == 1)
        // IETF protocol assignments (2001::/23): Teredo, benchmarking,
        // ORCHIDv2 and friends, excluded as one block (see above).
        || (first == 0x2001 && second < 0x0200)
        // Documentation (2001:db8::/32 and 3fff::/20).
        || (first == 0x2001 && second == 0x0db8)
        || (first == 0x3fff && second <= 0x0fff)
        // 6to4 (2002::/16).
        || first == 0x2002
        // Local-use IPv4/IPv6 translation (64:ff9b:1::/48). The well-known
        // NAT64 prefix 64:ff9b::/96 is globally reachable and handled by
        // `embedded_ipv4` instead.
        || (first == 0x0064 && second == 0xff9b && third == 0x0001)
        // Segment Routing (SRv6) SIDs (5f00::/16).
        || first == 0x5f00
    )
}

/// Unwrap the IPv4-mapped (`::ffff:a.b.c.d`), deprecated IPv4-compatible
/// (`::a.b.c.d`) and well-known NAT64 (`64:ff9b::a.b.c.d`) forms. Callers must
/// have ruled out `::` and `::1` first, since both also match the compatible
/// prefix.
///
/// NAT64 is unwrapped rather than rejected outright: on a DNS64 network every
/// public destination arrives in this shape, so excluding the prefix would
/// break IPv6-only clients, while screening the address it carries is what
/// keeps `64:ff9b::10.0.0.1` out.
pub(super) fn embedded_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    matches!(
        addr.segments(),
        [0, 0, 0, 0, 0, 0 | 0xffff, ..] | [0x0064, 0xff9b, 0, 0, 0, 0, ..]
    )
    .then(|| Ipv4Addr::from_bits(addr.to_bits() as u32))
}

/// Strict same-origin policy retained for callers that do not have a resolved
/// repository configuration. Production `RepoClient` instances use
/// `trusted_redirect_policy` with the configured repository and mirror
/// origins.
pub(crate) fn same_origin_redirect_policy() -> reqwest::redirect::Policy {
    trusted_redirect_policy(RedirectGuard::default())
}

pub(crate) fn redirect_rejection_from_reqwest(
    error: &reqwest::Error,
) -> Option<(RedirectRejectionKind, String)> {
    std::iter::successors(error.source(), |&current| current.source())
        .find_map(|current| current.downcast_ref::<RedirectPolicyError>())
        .map(|policy_error| (policy_error.kind, policy_error.details.clone()))
}
