use ark_ff::PrimeField;
use ark_std::{marker::PhantomData, rand::Rng};
use proof_essentials::vector_commitment::HomomorphicCommitmentScheme;

use crate::{
    folding_scheme::{self, FoldingCommitmentConfig},
    NonInteractiveFoldingScheme, PLONKFoldingScheme, RelaxedPLONKInstance, RelaxedPLONKWitness,
    StepCircuit, IVC,
};

/// A "pre-sangria" scheme. Implements IVC from a NIFS as described in Construction3 of Nova.
/// WARNING: this scheme is neither succinct nor zero-knowledge.
///
/// This scheme makes use of a main field and a help field. The trace resulting of running one step of the computation
/// is no longer in the MainField F_p, we have moved to some helper field F_q. Using cycles of curves, we can define a helper circuit
/// in F_q that allows us to cycle back to F_p in order to compute our next step in F_p again.
pub(crate) struct SangriaNoCompression<
    MainField: PrimeField,
    HelperField: PrimeField,
    Config: SangriaIVCConfig<MainField, HelperField>,
    SC: StepCircuit<MainField>,
>(PhantomData<(MainField, HelperField, Config, SC)>);

/// A `SangriaIVCConfig` is a trait that allows to bundle types related to an IVC instantiation.
/// By combining all the types here we avoid passing them as generics in structs such as `VerifierKey`, `ProverKey`, etc
pub trait SangriaIVCConfig<MainField: PrimeField, HelperField: PrimeField> {
    type MainCommitmentSchemes: FoldingCommitmentConfig<MainField>;

    type HelperCommitmentSchemes: FoldingCommitmentConfig<HelperField>;
}

/// Public parameters for the SangriaIVC scheme (no compression) contains commit parameters for the step circuit
/// in the main field, and commit parameters for the helper circuit in the helper field.
pub(crate) struct PublicParameters<
    MainField: PrimeField,
    HelperField: PrimeField,
    Config: SangriaIVCConfig<MainField, HelperField>,
> {
    pub main_nifs_pp: folding_scheme::PublicParameters<MainField, Config::MainCommitmentSchemes>,
    pub helper_nifs_pp:
        folding_scheme::PublicParameters<HelperField, Config::HelperCommitmentSchemes>,
}

/// The SangriaIVC VerifierKey contains verifier keys for the foldings of the main and helper
/// circuits. It also contains a description of the step circuit.
pub(crate) struct VerifierKey<
    MainField: PrimeField,
    HelperField: PrimeField,
    Config: SangriaIVCConfig<MainField, HelperField>,
    SC: StepCircuit<MainField>,
> {
    pub main_nifs_vk: folding_scheme::VerifierKey<MainField, Config::MainCommitmentSchemes>,
    pub helper_nifs_vk: folding_scheme::VerifierKey<HelperField, Config::HelperCommitmentSchemes>,
    pub step_circuit: SC,
}

/// The SangriaIVC ProverKey contains prover keys for the foldings of the main and helper
/// circuits. It also contains a description of the step circuit.
pub(crate) struct ProverKey<
    MainField: PrimeField,
    HelperField: PrimeField,
    Config: SangriaIVCConfig<MainField, HelperField>,
    SC: StepCircuit<MainField>,
> {
    pub main_nifs_pk: folding_scheme::ProverKey<MainField, Config::MainCommitmentSchemes>,
    pub helper_nifs_pk: folding_scheme::ProverKey<HelperField, Config::HelperCommitmentSchemes>,
    pub step_circuit: SC,
}

/// A half cycle proof is composed of two instance-witness pairs: one running instance-witness
/// that captures steps 0 to i-1 (via folding) and one instance-witness for the i-th step (the latest).
pub(crate) struct HalfCycleProof<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub latest_step_instance: RelaxedPLONKInstance<F, Comm>,
    pub latest_step_witness: RelaxedPLONKWitness<F>,
    pub running_instance: RelaxedPLONKInstance<F, Comm>,
    pub running_witness: RelaxedPLONKWitness<F>,
}

/// An IVC proof is composed of two half-cycle proofs. Each half cycle proof is composed
/// of two instance-witness pairs: one running instance-witness that captures steps 0 to i-1 (via folding)
/// and one instance-witness for the i-th step (the latest).
pub(crate) struct IVCProof<
    MainField: PrimeField,
    HelperField: PrimeField,
    Config: SangriaIVCConfig<MainField, HelperField>,
> {
    pub main_half_proof: HalfCycleProof<MainField, Config::MainCommitmentSchemes>,
    pub helper_half_proof: HalfCycleProof<HelperField, Config::HelperCommitmentSchemes>,
}

impl<MainField, HelperField, Config, SC> IVC<MainField, SC>
    for SangriaNoCompression<MainField, HelperField, Config, SC>
where
    MainField: PrimeField,
    HelperField: PrimeField,
    Config: SangriaIVCConfig<MainField, HelperField>,
    SC: StepCircuit<MainField>,
{
    type PublicParameters = PublicParameters<MainField, HelperField, Config>;
    type ProverKey = ProverKey<MainField, HelperField, Config, SC>;
    type VerifierKey = VerifierKey<MainField, HelperField, Config, SC>;
    type Proof = IVCProof<MainField, HelperField, Config>;

    fn setup<R: Rng>(rng: &mut R) -> Self::PublicParameters {
        todo!()
    }

    fn encode<R: Rng>(
        public_parameters: &Self::PublicParameters,
        step_circuit: &SC,
        rng: &mut R,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), crate::SangriaError> {
        todo!()
    }

    fn prove_step(
        prover_key: &Self::ProverKey,
        origin_state: &SC::State,
        current_state: SC::State,
        current_proof: Option<Self::Proof>,
        current_witness: &SC::Witness,
    ) -> Result<(SC::State, Self::Proof), crate::SangriaError> {
        todo!()
    }

    fn verify(
        verifier_key: &Self::VerifierKey,
        origin_state: &SC::State,
        current_state: SC::State,
        current_proof: Option<Self::Proof>,
    ) -> Result<(), crate::SangriaError> {
        todo!()
    }
}
