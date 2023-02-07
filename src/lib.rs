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
    /// Public parameters for the scheme.
    type PublicParameters;

    /// The structure of the underlying NP problem.
    type Structure;

    /// A collection of data needed for proving.
    type ProverKey;

    /// A collection of data needed for verifying.
    type VerifierKey;

    /// An instance of the relation that will be folded.
    type Instance;

    /// A witness for the relation to be folded.
    type Witness;

    /// The prover's message
    type ProverMessage;

    /// Run the randomised setup for the folding scheme to produce public parameters.
    fn setup<R: Rng>(rng: &mut R) -> Self::PublicParameters;

    /// Using the public parameters, run the randomised encoder that produces a prover key and verifier key.
    fn encode<R: Rng>(
        pp: &Self::PublicParameters,
        circuit: &Self::Structure,
        rng: &mut R,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), SangriaError>;

    /// The folding scheme prover. Outputs a folded instance-witness pair and the prover's message.
    fn prover(
        prover_key: &Self::ProverKey,
        left_instance: &Self::Instance,
        left_witness: &Self::Witness,
        right_instance: &Self::Instance,
        right_witness: &Self::Witness,
    ) -> Result<(Self::Instance, Self::Witness, Self::ProverMessage), SangriaError>;

    /// The folding scheme verifier. Outputs a folded instance.
    fn verifier(
        verifier_key: &Self::VerifierKey,
        left_instance: &Self::Instance,
        right_instance: &Self::Instance,
        prover_message: &Self::ProverMessage
    ) -> Result<Self::Instance, SangriaError>;
}

mod folding_scheme;
use ark_std::rand::Rng;
pub use folding_scheme::PLONKFoldingScheme;

mod ivc;

mod relaxed_plonk;
pub use relaxed_plonk::{PLONKCircuit, RelaxedPLONKInstance, RelaxedPLONKWitness};

mod sangria;
pub use sangria::Sangria;

mod errors;
pub use errors::SangriaError;
