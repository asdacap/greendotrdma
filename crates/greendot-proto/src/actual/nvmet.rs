//! The nvmet configfs view. The reader (`greendot_reconcile::actual::nvmet`)
//! fills these in from the live tree; a missing tree reads as empty.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActualNvmet {
    pub subsystems: Vec<Subsys>,
    pub ports: Vec<Port>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subsys {
    pub nqn: String,
    pub allow_any_host: bool,
    pub allowed_hosts: Vec<String>,
    pub namespaces: Vec<Namespace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Namespace {
    pub nsid: u32,
    pub device_path: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    pub id: u16,
    pub trtype: String,
    pub traddr: String,
    pub trsvcid: String,
    pub subsystems: Vec<String>,
}
