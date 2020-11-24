ERR_CERTIFICATE_CHAIN_VERIFICATION = 'Certificate chain verification failed.'
ERR_PROOF_EMPTY = 'Proof does not have any attestation'

class ProofEmptyError(Exception):
    def __init__(self):
        self.message = ERR_PROOF_EMPTY