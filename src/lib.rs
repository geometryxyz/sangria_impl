#![warn(missing_docs)]
//! Sangria is a Nova-like scheme for recursive zero-knowledge proofs. It implements incrementally
//! verifiable computation by using a folding for PLONK. We use a modified version of HyperPlonk to
//! compress the IVC proofs.

/// Interface for an IVC scheme
pub trait IVC {
    /// A collection of data needed for proving.
    type ProverKey;

    /// A collection of data needed for verifying.
    type VerifierKey;

    /// An IVC proof.
    type Proof;

    /// Run the IVC setup to produce public parameters.
    fn setup();

    /// Run the IVC encoder to produce a proving key and a verifying key.
    fn encode();

    /// Prove a step of the IVC computation.
    fn prove();

    /// Verify a step of the IVC computation.
    fn verify();
}

/// A marker trait for an IVC scheme which implements proof compression
pub trait IVCWithProofCompression: IVC {}

/// Interface for a non-interactive folding scheme (NIFS)
pub trait NonInteractiveFoldingScheme {
    /// A collection of data needed for proving.
    type ProverKey;

    /// A collection of data needed for verifying.
    type VerifierKey;

    /// An instance of the relation that will be folded.
    type Instance;

    /// A witness for the relation to be folded.
    type Witness;

    /// The folding scheme prover. Outputs a folded instance-witness pair.
    fn prover();

    /// The folding scheme verifier. Outputs a folded instance.
    fn verifier();
}

mod folding_scheme;
pub use folding_scheme::PLONKFoldingScheme;

mod ivc;

mod relaxed_plonk;
pub use relaxed_plonk::{PLONKCircuit, RelaxedPLONKInstance, RelaxedPLONKWitness};

mod sangria;
pub use sangria::Sangria;
