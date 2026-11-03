//! Recorder for the web demo: steps, narration, frames, engine events and party state, in
//! the order they happened. Disabled unless [`enable`] is called (tests never record).

use std::sync::Mutex;

use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Item {
    Step { id: String, title: String },
    Note { text: String },
    /// A message between parties. `cls`: link-a | link-b | link-c | presign | hello | quorum |
    /// media | api | chain | fault.
    Msg { from: String, to: String, label: String, detail: String, cls: String },
    /// Something a party recorded. `level`: ok | info | warn | fault | display.
    Event { who: String, text: String, level: String },
    State(State),
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct State {
    pub hot_on: bool,
    pub hot_counter: u64,
    pub frozen_hot: bool,
    pub frozen_cold: bool,
    pub frozen_prod: bool,
    pub prod_pool: usize,
    pub cold_pool: usize,
    pub broadcasts: usize,
    pub prod_revoked: bool,
    pub prod_gen: u32,
    pub media: usize,
}

static REC: Mutex<Option<Vec<Item>>> = Mutex::new(None);

pub fn enable() {
    *REC.lock().unwrap() = Some(Vec::new());
}

pub fn push(i: Item) {
    if let Some(v) = REC.lock().unwrap().as_mut() {
        v.push(i);
    }
}

pub fn take() -> Vec<Item> {
    REC.lock().unwrap().take().unwrap_or_default()
}

pub fn msg(from: &str, to: &str, label: impl Into<String>, detail: impl Into<String>, cls: &str) {
    push(Item::Msg { from: from.trim().into(), to: to.trim().into(), label: label.into(), detail: detail.into(), cls: cls.into() });
}

pub fn step(id: &str, title: &str) {
    push(Item::Step { id: id.into(), title: title.into() });
}

pub fn note(t: impl Into<String>) {
    push(Item::Note { text: t.into() });
}

pub fn event(who: &str, text: impl Into<String>, level: &str) {
    push(Item::Event { who: who.into(), text: text.into(), level: level.into() });
}
