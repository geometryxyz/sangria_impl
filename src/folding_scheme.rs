use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use proof_essentials::vector_commitment::HomomorphicCommitmentScheme;

use crate::{
    NonInteractiveFoldingScheme, PLONKCircuit, RelaxedPLONKInstance, RelaxedPLONKWitness,
    SangriaError,
};

/// A folding scheme for relaxed PLONK
pub struct PLONKFoldingScheme<F: PrimeField, Comm: FoldingCommitmentConfig<F>>(
    PhantomData<(F, Comm)>,
);

pub trait FoldingCommitmentConfig<F: PrimeField> {
    type CommitmentSlack: HomomorphicCommitmentScheme<F>;
    type CommitmentWitness: HomomorphicCommitmentScheme<F>;
}

/// Public parameters for the folding scheme. Contains size parameters for the PLONK circuits
/// and commitment parameters for vectors of sizes `number_of_gates` and `number_of_public_inputs + number_of_gates + 1`
pub struct PublicParameters<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub number_of_public_inputs: usize,
    pub number_of_gates: usize,
    pub commit_key_witness: <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::CommitKey,
    pub commit_key_selectors_and_slack:
        <Comm::CommitmentWitness as HomomorphicCommitmentScheme<F>>::CommitKey,
}

/// The verifier key for the PLONK folding scheme. Contains a commitment to the q_C selector (constant)
pub struct VerifierKey<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub selector_c_commitment:
        <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::Commitment,
}

/// Prover key for the PLONK folding scheme. Contains:
/// - a commitment to the q_C selector (as the verifier key)
/// - a description of the circuit (needed to compute cross terms)
/// - commitment parameters (as the public parameters)
/// - the randomness that was used to commit to q_C
pub struct ProverKey<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub circuit: PLONKCircuit,
    pub public_parameters: PublicParameters<F, Comm>,
    pub verifier_key: VerifierKey<F, Comm>,
    pub selector_c_commit_randomness: F,
}

impl<F, Comm> NonInteractiveFoldingScheme for PLONKFoldingScheme<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    type PublicParameters = PublicParameters<F, Comm>;
    type Structure = PLONKCircuit;
    type Instance = RelaxedPLONKInstance<F, Comm>;
    type Witness = RelaxedPLONKWitness<F>;
    type ProverKey = ProverKey<F, Comm>;
    type VerifierKey = VerifierKey<F, Comm>;
    type ProverMessage = <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::Commitment;

    fn setup<R: ark_std::rand::Rng>(rng: &mut R) -> Self::PublicParameters {
        todo!()
    }

    fn encode<R: ark_std::rand::Rng>(
        pp: &Self::PublicParameters,
        circuit: &Self::Structure,
        rng: &mut R,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), SangriaError> {
        todo!()
    }

    fn prover(
        prover_key: &Self::ProverKey,
        left_instance: &Self::Instance,
        left_witness: &Self::Witness,
        right_instance: &Self::Instance,
        right_witness: &Self::Witness,
    ) -> Result<(Self::Instance, Self::Witness, Self::ProverMessage), SangriaError> {
        todo!()
    }

    fn verifier(
        verifier_key: &Self::VerifierKey,
        left_instance: &Self::Instance,
        right_instance: &Self::Instance,
        prover_message: &Self::ProverMessage,
    ) -> Result<Self::Instance, SangriaError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {}
