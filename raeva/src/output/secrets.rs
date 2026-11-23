//! The values of the secrets the configuration took, which nothing raeva
//! prints may show ([`rv_config::redact_secrets`]). raeva's own unit tests
//! read a registry of their thread's, as the configurations other tests
//! load register short passwords such as `p` that would mask their text.

use std::borrow::Cow;

#[cfg(not(test))]
pub(crate) fn redact_secrets(text: &str) -> Cow<'_, str> {
    rv_config::redact_secrets(text)
}

#[cfg(not(test))]
pub(crate) fn redact_secrets_in_json(json: &str) -> Cow<'_, str> {
    rv_config::redact_secrets_in_json(json)
}

#[cfg(test)]
thread_local! {
    static SECRETS: std::cell::RefCell<rv_config::Redactor> =
        const { std::cell::RefCell::new(rv_config::Redactor::new()) };
}

/// Hide `value` from what this test thread prints.
#[cfg(test)]
pub(crate) fn register_secret(value: &str) {
    SECRETS.with(|secrets| secrets.borrow_mut().register(value));
}

#[cfg(test)]
pub(crate) fn redact_secrets(text: &str) -> Cow<'_, str> {
    SECRETS.with(|secrets| secrets.borrow().redact(text))
}

#[cfg(test)]
pub(crate) fn redact_secrets_in_json(json: &str) -> Cow<'_, str> {
    SECRETS.with(|secrets| secrets.borrow().redact_json(json))
}
