use crate::vector_commitment::HomomorphicCommitmentScheme;
use ark_ff::PrimeField;
use ark_sponge::{
    poseidon::{PoseidonParameters, PoseidonSponge},
    Absorb, CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_std::{marker::PhantomData, rand::Rng};

use crate::{
    NonInteractiveFoldingScheme, PLONKCircuit, RelaxedPLONKInstance, RelaxedPLONKWitness,
    SangriaError, CONSTANT_SELECTOR_INDEX,
};

/// A folding scheme for relaxed PLONK
pub struct PLONKFoldingScheme<
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
    RO: FieldBasedCryptographicSponge<F>,
>(PhantomData<(F, Comm, RO)>);

pub trait FoldingCommitmentConfig<F: PrimeField> {
    type CommitmentSlack: HomomorphicCommitmentScheme<F>;
    type CommitmentWitness: HomomorphicCommitmentScheme<F>;
}

pub struct SetupInfo<F: PrimeField> {
    pub number_of_public_inputs: usize,
    pub number_of_gates: usize,
    pub domain_separator: Vec<u8>,
    pub poseidon_constants: PoseidonParameters<F>,
}

/// Public parameters for the folding scheme. Contains size parameters for the PLONK circuits
/// and commitment parameters for vectors of sizes `number_of_gates` and `number_of_public_inputs + number_of_gates + 1`
pub struct PublicParameters<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub number_of_public_inputs: usize,
    pub number_of_gates: usize,
    pub commit_key_witness: <Comm::CommitmentWitness as HomomorphicCommitmentScheme<F>>::CommitKey,
    pub commit_key_selectors_and_slack:
        <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::CommitKey,
    pub poseidon_constants: PoseidonParameters<F>,

    pub domain_separator: Vec<u8>,
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
            poseidon_constants: self.poseidon_constants.clone(),
            domain_separator: self.domain_separator.clone(),
        }
    }
}

impl<F, Comm> Absorb for PublicParameters<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    fn to_sponge_bytes(&self, _dest: &mut Vec<u8>) {
        todo!()
    }

    fn to_sponge_field_elements<SpongeF: PrimeField>(&self, _dest: &mut Vec<SpongeF>) {
        todo!()
    }
}

/// The verifier key for the PLONK folding scheme. Contains a commitment to the q_C selector (constant)
pub struct VerifierKey<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub selector_c_commitment:
        <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::Commitment,
    pub transcript_seed: F,
}

impl<F, Comm> Clone for VerifierKey<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    fn clone(&self) -> Self {
        Self {
            selector_c_commitment: self.selector_c_commitment,
            transcript_seed: self.transcript_seed,
        }
    }
}

impl<F, Comm> Absorb for VerifierKey<F, Comm>
where
    F: PrimeField,
    Comm: FoldingCommitmentConfig<F>,
{
    fn to_sponge_bytes(&self, _dest: &mut Vec<u8>) {
        todo!()
    }

    fn to_sponge_field_elements<SpongeF: PrimeField>(&self, _dest: &mut Vec<SpongeF>) {
        todo!()
    }
}

/// Prover key for the PLONK folding scheme. Contains:
/// - a commitment to the q_C selector (as the verifier key)
/// - a description of the circuit (needed to compute cross terms)
/// - commitment parameters (as the public parameters)
/// - the randomness that was used to commit to q_C
pub struct ProverKey<F: PrimeField, Comm: FoldingCommitmentConfig<F>> {
    pub verifier_key: VerifierKey<F, Comm>,
    pub circuit: PLONKCircuit<F>,
    pub selector_c_commit_randomness: F,
}

impl<F, Comm> NonInteractiveFoldingScheme for PLONKFoldingScheme<F, Comm, PoseidonSponge<F>>
where
    F: PrimeField + Absorb,
    Comm: FoldingCommitmentConfig<F>,
{
    type SetupInfo = SetupInfo<F>;
    type PublicParameters = PublicParameters<F, Comm>;
    type Structure = PLONKCircuit<F>;
    type Instance = RelaxedPLONKInstance<F, Comm>;
    type Witness = RelaxedPLONKWitness<F>;
    type ProverKey = ProverKey<F, Comm>;
    type VerifierKey = VerifierKey<F, Comm>;
    type ProverMessage = <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::Commitment;

    fn setup<R: Rng>(info: &SetupInfo<F>, rng: &mut R) -> Self::PublicParameters {
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
            domain_separator: info.domain_separator.clone(),
            poseidon_constants: info.poseidon_constants.clone(),
        }
    }

    fn encode<R: Rng>(
        pp: &Self::PublicParameters,
        circuit: &Self::Structure,
        rng: &mut R,
    ) -> Result<(Self::ProverKey, Self::VerifierKey), SangriaError> {
        let randomness_c = F::rand(rng);

        let c_selector = circuit.single_selector(CONSTANT_SELECTOR_INDEX)?;
        let commitment_q_c = <Comm::CommitmentSlack as HomomorphicCommitmentScheme<F>>::commit(
            &pp.commit_key_selectors_and_slack,
            &c_selector,
            randomness_c,
        )?;

        let mut sponge = PoseidonSponge::new(&pp.poseidon_constants);

        sponge.absorb(circuit);
        sponge.absorb(pp);
        sponge.absorb(&randomness_c);
        let transcript_seed = sponge.squeeze_native_field_elements(1);

        let vk: VerifierKey<F, Comm> = VerifierKey {
            selector_c_commitment: commitment_q_c,
            transcript_seed: transcript_seed[0],
        };

        let pk = ProverKey {
            circuit: circuit.clone(),
            verifier_key: vk.clone(),
            selector_c_commit_randomness: randomness_c,
        };

        Ok((pk, vk))
    }

    fn prover(
        _public_parameters: &Self::PublicParameters,
        _prover_key: &Self::ProverKey,
        _left_instance: &Self::Instance,
        _left_witness: &Self::Witness,
        _right_instance: &Self::Instance,
        _right_witness: &Self::Witness,
    ) -> Result<(Self::Instance, Self::Witness, Self::ProverMessage), SangriaError> {
        todo!()
    }

    fn verifier(
        public_parameters: &Self::PublicParameters,
        verifier_key: &Self::VerifierKey,
        left_instance: &Self::Instance,
        right_instance: &Self::Instance,
        prover_message: &Self::ProverMessage,
    ) -> Result<Self::Instance, SangriaError> {
        let mut sponge = PoseidonSponge::new(&public_parameters.poseidon_constants);

        sponge.absorb(&verifier_key);
        sponge.absorb(&left_instance);
        sponge.absorb(&right_instance);
        sponge.absorb(&prover_message);
        let challenge: F = sponge.squeeze_field_elements(1)[0];

        let folded_instance = right_instance.clone() * challenge + left_instance;

        Ok(folded_instance)
    }
}

#[cfg(test)]
mod tests {}
