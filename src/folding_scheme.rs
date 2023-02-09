use ark_ff::PrimeField;
use ark_std::{marker::PhantomData, rand::Rng};
use proof_essentials::vector_commitment::HomomorphicCommitmentScheme;

use crate::{
    NonInteractiveFoldingScheme, PLONKCircuit, RelaxedPLONKInstance, RelaxedPLONKWitness,
    SangriaError, CONSTANT_SELECTOR_INDEX,
};

/// A folding scheme for relaxed PLONK
pub struct PLONKFoldingScheme<F: PrimeField, Comm: FoldingCommitmentConfig<F>>(
    PhantomData<(F, Comm)>,
);

pub trait FoldingCommitmentConfig<F: PrimeField> {
    type CommitmentSlack: HomomorphicCommitmentScheme<F>;
    type CommitmentWitness: HomomorphicCommitmentScheme<F>;
}

pub struct SetupInfo {
    pub number_of_public_inputs: usize,
    pub number_of_gates: usize,
}

/// Public parameters for the folding scheme. Contains size parameters for the PLONK circuits
/// and commitment parameters for vectors of sizes `number_of_gates` and `number_of_public_inputs + number_of_gates + 1`
pub struct PublicParameters<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub number_of_public_inputs: usize,
    pub number_of_gates: usize,
    pub commit_key_witness: <Comm::CommitmentWitness as HomomorphicCommitmentScheme<F>>::CommitKey,
    pub commit_key_selectors_and_slack:
        <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::CommitKey,
}

impl<F, Comm> Clone for PublicParameters<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    fn clone(&self) -> Self {
        Self {
            number_of_public_inputs: self.number_of_public_inputs,
            number_of_gates: self.number_of_gates,
            commit_key_witness: self.commit_key_witness.clone(),
            commit_key_selectors_and_slack: self.commit_key_selectors_and_slack.clone(),
        }
    }
}

/// The verifier key for the PLONK folding scheme. Contains a commitment to the q_C selector (constant)
pub struct VerifierKey<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub selector_c_commitment:
        <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::Commitment,
}

impl<F, Comm> Clone for VerifierKey<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    fn clone(&self) -> Self {
        Self {
            selector_c_commitment: self.selector_c_commitment.clone(),
        }
    }
}

/// Prover key for the PLONK folding scheme. Contains:
/// - a commitment to the q_C selector (as the verifier key)
/// - a description of the circuit (needed to compute cross terms)
/// - commitment parameters (as the public parameters)
/// - the randomness that was used to commit to q_C
pub struct ProverKey<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub circuit: PLONKCircuit<F>,
    pub public_parameters: PublicParameters<F, Comm>,
    pub verifier_key: VerifierKey<F, Comm>,
    pub selector_c_commit_randomness: F,
}

impl<F, Comm> NonInteractiveFoldingScheme for PLONKFoldingScheme<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    type SetupInfo = SetupInfo;
    type PublicParameters = PublicParameters<F, Comm>;
    type Structure = PLONKCircuit<F>;
    type Instance = RelaxedPLONKInstance<F, Comm>;
    type Witness = RelaxedPLONKWitness<F>;
    type ProverKey = ProverKey<F, Comm>;
    type VerifierKey = VerifierKey<F, Comm>;
    type ProverMessage = <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::Commitment;

    fn setup<R: Rng>(info: &SetupInfo, rng: &mut R) -> PublicParameters<F, Comm> {
        let commit_key_witness = <Comm::CommitmentWitness as HomomorphicCommitmentScheme<F>>::setup(
            rng,
            info.number_of_gates,
        );
        let commit_key_selectors_and_slack =
            <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::setup(
                rng,
                info.number_of_gates + info.number_of_public_inputs + 1,
            );

        PublicParameters {
            number_of_gates: info.number_of_gates,
            number_of_public_inputs: info.number_of_public_inputs,
            commit_key_witness,
            commit_key_selectors_and_slack,
        }
    }

    fn encode<R: ark_std::rand::Rng>(
        pp: &PublicParameters<F, Comm>,
        circuit: &PLONKCircuit<F>,
        rng: &mut R,
    ) -> Result<(ProverKey<F, Comm>, VerifierKey<F, Comm>), SangriaError> {
        let randomness_c = F::rand(rng);

        let c_selector = circuit.single_selector(CONSTANT_SELECTOR_INDEX)?;
        let commitment_q_c = <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::commit(
            &pp.commit_key_selectors_and_slack,
            &c_selector,
            randomness_c,
        )?;

        let vk: VerifierKey<F, Comm> = VerifierKey {
            selector_c_commitment: commitment_q_c,
        };

        let pk = ProverKey {
            circuit: circuit.clone(),
            verifier_key: vk.clone(),
            public_parameters: pp.clone(),
            selector_c_commit_randomness: randomness_c,
        };

        Ok((pk, vk))
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
