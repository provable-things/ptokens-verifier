"""Defined the proof object
"""
import logging
import json

from base64 import (
    b64decode,
    urlsafe_b64encode,
)

import cbor2
import codecs

from pyasn1.codec.ber import decoder
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.backends import default_backend

from utils.constants import (
    FIELD_TYPE,
    FIELD_VERSION,
    FIELD_COMMITMENT,
    FIELD_COMMITMENT_TS,
    FIELD_SIGNED_COMMITMENT,
    FIELD_STRONGBOX_ATTESTATION,
    FIELD_SAFETYNET_ATTESTATION,
    GOOGLE_ROOT_PUBLIK_KEY,
)

from utils.errors import ProofEmptyError

from utils.logger import Logger
from utils.schemas.google_attestation import (
    KeyDescription,
    AttestationApplicationId
)

class Proof(object):
    """Represent a proof object
    """
    def __init__(
        self,
        proof_type,
        version,
        commitment,
        commitment_timestamp,
        signed_commitment,
        snet_att,
        cert_att
    ):
        """Instantiate a proof object

        Arguments:
            proof_type {[str]} -- proof type
            version {[str]} -- proof version
            commitment {[bytearray]} -- base64 enc of the bytearray composed of
                                        [version|commitment_timestamp|cbor_commitment]
            commitment_timestamp {[int]} -- unix timestamp when the commitment
                                            created
            signed_commitment {[bytes]} -- signature of the sha256 of the commitment
            snet_att {[str]} -- base64 enc of the cbor serialization
                                of the safetynet response
            cert_att {[str]} -- base64 enc of the cbor serialization
                                of the strongbox attestation
        """
        self.type = proof_type
        self.version = version
        self.commitment = b64decode(commitment)
        self.commitment_timestamp = commitment_timestamp
        self.signed_commitment = b64decode(signed_commitment)
        self.safetynet_attestation = cbor2.loads(b64decode(snet_att)) if snet_att else ""
        self.strongbox_attestation = cbor2.loads(b64decode(cert_att)) if cert_att else ""

        if not self.safetynet_attestation and not self.strongbox_attestation:
            raise ProofEmptyError()

        self.logger = Logger(__name__, logging.DEBUG)

    def set_logger(self, logger):
        self.logger = logger

    def to_string(self):
        return """type {}
            version {}
            commitment {}
            signed_commitment {}
            safetynet_attestation {}
            strongbox_attestation {}""".format(
                self.type,
                self.version,
                self.commitment,
                self.signed_commitment,
                self.safetynet_attestation,
                self.strongbox_attestation
            )

    def verify_certificate_chain(self):
        """Verify the extracted certificate chain

        Returns:
            bool -- True if the signatures were verified
            correctly, False otherwise
        """

        if not self.strongbox_attestation:
            self.logger.warning("Certificate chain verification skipped...")
            return True

        self.logger.debug('Verifying certificate chain')
        leaf = x509.load_der_x509_certificate(
            self.strongbox_attestation['leaf'],
            default_backend()
        )
        inter = x509.load_der_x509_certificate(
            self.strongbox_attestation['intermediate'],
            default_backend()
        )

        root = x509.load_der_x509_certificate(
            self.strongbox_attestation['root'],
            default_backend()
        )
        google = x509.load_pem_x509_certificate(
            GOOGLE_ROOT_PUBLIK_KEY,
            default_backend()
        )

        try:
            inter.public_key().verify(
                leaf.signature,
                leaf.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            root.public_key().verify(
                inter.signature,
                inter.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256())
            )

            google.public_key().verify(
                root.signature,
                root.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            google.public_key().verify(
                google.signature,
                google.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

        except InvalidSignature:
            return False

        return True

    def verify_signed_commitment(self):
        """Verify the attestation signed commitment


        The proofs comes with the sha256 of the
        commitment signed with the attestion key,
        the commitment is a byte sequence consisting in

            [version|timestamp|core state]

        The attestaion key can be found inside the
        leaf certificate of the strongbox proof.

        Returns:
            bool -- True if the signature is verified,
                    False otherwise
        """

        if not self.strongbox_attestation:
            self.logger.warning("Signed commitment verification skipped...")
            return True

        self.logger.debug('Verifying signed commitment...')
        leaf = x509.load_der_x509_certificate(
            self.strongbox_attestation['leaf'],
            default_backend()
        )

        try:
            leaf.public_key().verify(
                self.signed_commitment,
                self.commitment,
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            return False

        return True

    def __extract_google_certificate(self):
        header_obj = json.loads(self.safetynet_attestation['JWS_Header'])
        google_certificate = b64decode(header_obj['x5c'][0])

        return x509.load_der_x509_certificate(
            google_certificate,
            default_backend()
        )

    def verify_jws(self):
        """Verify the given JWS signed by Google
        returned by Google.

        Arguments:
            googl_api_key {[str]} -- Google api key to make the
                                     JWS signature verification

        Returns:
            bool -- True if the verifycation succeed,
                    False otherwise
        """

        if not self.safetynet_attestation:
            self.logger.warning("JWS verification skipped...")
            return True

        self.logger.debug('Verifying SafetyNet response...')

        header = self.safetynet_attestation['JWS_Header']
        payload = self.safetynet_attestation['JWS_Payload']
        signature = self.safetynet_attestation['JWS_Signature']

        # Remove all special characters from the base64 encoded
        # string as per RFC 7515
        enc_header = urlsafe_b64encode(header).decode().replace('=', '')
        enc_payload = urlsafe_b64encode(payload).decode().replace('=', '')

        google_certificate = self.__extract_google_certificate()
        data = enc_header + '.' + enc_payload

        try:
            google_certificate.public_key().verify(
                signature,
                data.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False

        return True

    def verify_strongbox_leaf_cert_digest(self, apk_cert_sha256_digest):
        """Verifies the apk certificate digest match the one stated
        inside the leaf attestation certificate chain.

        Arguments:
            apk_cert_sha256_digest {str} -- apk signer certificate digest
        """

        if not self.strongbox_attestation:
            self.logger.warning("Leaf certificate digest verification skipped...")
            return True

        leaf = x509.load_der_x509_certificate(
            self.strongbox_attestation['leaf'],
            default_backend()
        )

        leaf_cert = decoder.decode(
            leaf.extensions[1].value.value,
            asn1Spec=KeyDescription()
        )[0]

        att_app_id = decoder.decode(
            leaf_cert['softwareEnforced']['attestationApplicationId'],
            asn1Spec=AttestationApplicationId()
        )[0]

        leaf_certificate_digest = bytes(att_app_id['signature'][0].asNumbers())

        return leaf_certificate_digest == apk_cert_sha256_digest

    def verify_safetynet(self, apk_sha256_digest, apk_cert_sha256_digest):
        """Check the sha256 of the APK and the sha256 of the apk'signer
        certificate is the same as the ones stated by the SafetyNet Prood


        Arguments:
            apk_sha256_digest {bytes} -- sha256sum of the APK
            apk_cert_sha256_digest {bytes} -- sha256 sum of the signer's
                                            certificate (Get this using the
                                            apksigner tool inside the android SDK)
        Returns:
            bool -- True if the comparison succeed, False otherwise
        """

        if not self.safetynet_attestation:
            self.logger.warning("Safetynet verification skipped...")
            return True

        payload = json.loads(self.safetynet_attestation['JWS_Payload'])
        payload_apk_digest = b64decode(payload['apkDigestSha256'])
        payload_apk_cert_digest = b64decode(payload['apkCertificateDigestSha256'][0])

        cond1 = (payload_apk_digest == apk_sha256_digest)
        cond2 = (payload_apk_cert_digest == apk_cert_sha256_digest)

        return cond1 and cond2


    def verify_all(self, apkhash, apkcerthash):
        passed = self.verify_jws() and \
            self.verify_signed_commitment() and \
            self.verify_certificate_chain() and \
            self.verify_safetynet(apkhash, apkcerthash) and \
            self.verify_strongbox_leaf_cert_digest(apkcerthash)

        return passed

    def get_attested_message(self):
        if not self.commitment:
            raise ProofEmptyError()
        return cbor2.loads(self.commitment[5:])

    @staticmethod
    def parse(filename):
        """Parse a proof stored in a json file
        """
        with open(filename, 'r') as file_obj:
            j = json.loads(file_obj.read())
            strongbox_attestation = j[FIELD_STRONGBOX_ATTESTATION]
            safetynet_attestation = j[FIELD_SAFETYNET_ATTESTATION]
            commitment = j[FIELD_COMMITMENT]
            commitment_ts = j[FIELD_COMMITMENT_TS]
            signed_commitment = j[FIELD_SIGNED_COMMITMENT]
            version = j[FIELD_VERSION]
            ptype = j[FIELD_TYPE]

            return Proof(
                ptype,
                version,
                commitment,
                commitment_ts,
                signed_commitment,
                safetynet_attestation,
                strongbox_attestation
            )
