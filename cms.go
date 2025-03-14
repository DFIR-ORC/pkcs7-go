package pkcs7

import (
	"hash"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// unwrapRSAOAEPPKCS8 decrypt using RSA OAEP
func unwrapRSAOAEPPKCS8(ciphertext []byte, h hash.Hash, pkey *rsa.PrivateKey) ([]byte, error) {
	label := []byte("") // Optional label, can be nil
	plaintext, err := rsa.DecryptOAEP(h, rand.Reader, pkey, ciphertext, label)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// unwrapRSAPKCS8 decrypt using PKCS#1 RSA
func unwrapRSAPKCS8(ciphertext []byte, pkey *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, pkey, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// findAndUnwrapSessionKey finds and decrypts the session key for the given private key
func findAndUnwrapSessionKey(envelope *envelopedData, pkey *rsa.PrivateKey) (*recipientInfo, []byte, error) {
	for _, ri := range envelope.RecipientInfos {

		if log.GetLevel() >= log.TraceLevel {
			data, _ := json.MarshalIndent(ri, "", "\t")
			log.Tracef("CMS: Recipient: %s\n", data)
			log.Debugf("CMS: KekAlgo: %v\n", ri.KeyEncryptionAlgorithm)
		}
		if OIDEncryptionAlgorithmRSA.Equal(ri.KeyEncryptionAlgorithm.Algorithm) {
			// Old school PKCS#1 RSA
			log.Debugf("CMS: decrypting session key with RSA PKCS#1")
			var contentKey []byte
			contentKey, err := unwrapRSAPKCS8(ri.EncryptedKey, pkey)
			if err == nil {
				log.Trace("CMS: sucessfully decrypted content key wrapped with RSA PKCS#1")
				return &ri, contentKey, nil
			} else {
				log.Tracef("CMS: failed to decrypt content key wrapped with RSA PKCS#1: %v", err)
			}

		} else if OIDEncryptionAlgorithmRSAOAEPSHA1.Equal(ri.KeyEncryptionAlgorithm.Algorithm) {
			////// RSA OAEP SHA1
			log.Debugf("CMS: decrypting session key with RSA-OAEP-SHA1")
			var contentKey []byte
			contentKey, err := unwrapRSAOAEPPKCS8(ri.EncryptedKey, sha1.New(), pkey)
			if err == nil {
				log.Trace("CMS: sucessfully decrypted content key wrapped with RSA-OAEP-SHA1")
				return &ri, contentKey, nil
			} else {
				log.Tracef("CMS: failed to decrypt content key wrapped with RSA-OAEP-SHA1: %v", err)
			}

		} else if OIDEncryptionAlgorithmRSAOAEPSHA256.Equal(ri.KeyEncryptionAlgorithm.Algorithm) {
			///// RSA OAEP SHA256
			log.Debugf("CMS: decrypting session key with RSA-OAEP-SHA256")
			var contentKey []byte
			contentKey, err := unwrapRSAOAEPPKCS8(ri.EncryptedKey, sha256.New(), pkey)

			if err == nil {
				log.Trace("CMS: sucessfully decrypted content key wrapped with RSA-OAEP-SHA256")
				return &ri, contentKey, nil
			} else {
				log.Tracef("CMS: failed to decrypt content key wrapped with RSAO-OAEP-SHA256: %v", err)
			}

		} else {
			///// Something else unsupported
			return nil, nil, fmt.Errorf("unsupported key encryption algorithm: %v", ri.KeyEncryptionAlgorithm)
		}

	}
	log.Tracef("CMS: failed to find a recipient for our private key")
	return nil, nil, nil

}

// DecryptEnvelope decrypt decrypts encrypted content info for recipient cert and private key
func (envelope *envelopedData) DecryptUsingPrivateKey(pkey *rsa.PrivateKey) ([]byte, error) {

	rcpt, contentKey, err := findAndUnwrapSessionKey(envelope, pkey)
	if err != nil {
		return nil, err
	}
	if rcpt == nil {
		return nil, fmt.Errorf("no KeK found for the private key")
	}

	clearText, err := envelope.EncryptedContentInfo.decrypt(contentKey)
	return clearText, err
}

func (p7 *PKCS7) DecryptUsingPrivateKey(pkey *rsa.PrivateKey) ([]byte, error) {
	envelope, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	return envelope.DecryptUsingPrivateKey(pkey)
}

//eof
