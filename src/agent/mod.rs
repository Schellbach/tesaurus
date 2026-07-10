//! Local agent co-signer: policy checks + HTTP API.

mod policy;
mod server;

pub use policy::{AgentPolicy, PolicyContext};
pub use server::{run_agent_server, SignRequest, SignResponse};
