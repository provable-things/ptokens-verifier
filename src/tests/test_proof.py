import pytest

from hashlib import sha256
from utils.proof import Proof
from utils.errors import ProofEmptyError

from res import (
    RESOURCE_APP_DEBUG_APK,
    PROOF_ANDROID_COMPLETE,
    RESOURCE_APK_CERTIFICATE_DIGEST,
    PROOF_ANDROID_EMPTY,
    PROOF_ANDROID_STRONGBOX_ONLY,
    PROOF_ANDROID_SAFETYNET_ONLY,
)

@pytest.fixture
def proof_sample():
    return Proof.parse(
        PROOF_ANDROID_COMPLETE
    )

@pytest.fixture
def proof_sample_wout_safetynet():
    return Proof.parse(
        PROOF_ANDROID_STRONGBOX_ONLY,
    )

@pytest.fixture
def proof_sample_wout_strongbox():
    return Proof.parse(
        PROOF_ANDROID_SAFETYNET_ONLY,
    )

def test_parse(proof_sample):
    assert proof_sample.version == 0
    assert proof_sample.type == 'strongbox'
    assert len(proof_sample.commitment) > 0
    assert proof_sample.commitment_timestamp > 0
    assert len(proof_sample.signed_commitment) > 0
    assert len(proof_sample.strongbox_attestation) > 0
    assert proof_sample.safetynet_attestation is not None

def test_verify_certificate_chain_succeed(proof_sample):
    assert proof_sample.verify_certificate_chain() == True

def test_verify_signed_commitment_fails(proof_sample):
    proof_sample.commitment = b"""we change the signed msg
    so the signature validation will fail"""

    assert proof_sample.verify_signed_commitment() == False

def test_verify_signed_commitment_succeed(proof_sample):
    assert proof_sample.verify_signed_commitment() == True

def test_verify_jws_succeed(proof_sample):
    assert proof_sample.verify_jws() == True

def test_verify_safetynet(proof_sample):
    apk = open(RESOURCE_APP_DEBUG_APK, 'rb').read()
    hash = sha256(apk)
    apk_cert_digest = bytes.fromhex(RESOURCE_APK_CERTIFICATE_DIGEST)

    assert proof_sample.verify_safetynet(hash.digest(), apk_cert_digest)

def test_verify_strongbox_leaf_cert_digest(proof_sample):
    apk_cert_digest = bytes.fromhex(RESOURCE_APK_CERTIFICATE_DIGEST)
    assert proof_sample.verify_strongbox_leaf_cert_digest(apk_cert_digest)

def test_verify_strongbox_only_proof(proof_sample_wout_safetynet):
    apk = open(RESOURCE_APP_DEBUG_APK, 'rb').read()
    hash = sha256(apk)
    apk_cert_digest = bytes.fromhex(RESOURCE_APK_CERTIFICATE_DIGEST)

    assert proof_sample_wout_safetynet.verify_all(hash.digest(), apk_cert_digest)


def test_verify_safetynetonly_proof(proof_sample_wout_strongbox):
    apk = open(RESOURCE_APP_DEBUG_APK, 'rb').read()
    hash = sha256(apk)
    apk_cert_digest = bytes.fromhex(RESOURCE_APK_CERTIFICATE_DIGEST)

    assert proof_sample_wout_strongbox.verify_all(hash.digest(), apk_cert_digest)


def test_verify_safetynet_for_a_proof_wout_attestations():
    with pytest.raises(ProofEmptyError):
        Proof.parse(PROOF_ANDROID_EMPTY)
