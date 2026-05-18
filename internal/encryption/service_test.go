package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

type fakeKeyRepository struct {
	keys map[string]*PublicKey
}

func (r *fakeKeyRepository) UpsertPublicKey(ctx context.Context, userID, publicKey string) (*PublicKey, error) {
	key := &PublicKey{
		UserID:    userID,
		PublicKey: publicKey,
		Algorithm: Algorithm,
	}
	r.keys[userID] = key
	return key, nil
}

func (r *fakeKeyRepository) GetPublicKey(ctx context.Context, userID string) (*PublicKey, error) {
	return r.keys[userID], nil
}

func (r *fakeKeyRepository) LookupPublicKeys(ctx context.Context, userIDs []string) ([]*PublicKey, error) {
	keys := make([]*PublicKey, 0, len(userIDs))
	for _, userID := range userIDs {
		if key := r.keys[userID]; key != nil {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func TestEncryptMessageCanBeOpenedByRecipient(t *testing.T) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	svc := NewService(&fakeKeyRepository{
		keys: map[string]*PublicKey{
			"user1": {
				UserID:    "user1",
				PublicKey: base64.StdEncoding.EncodeToString(publicKey[:]),
				Algorithm: Algorithm,
			},
		},
	})

	envelopes, err := svc.EncryptMessage(context.Background(), "hello", []Recipient{{UserID: "user1"}})
	if err != nil {
		t.Fatalf("encrypt message: %v", err)
	}
	if len(envelopes) != 1 {
		t.Fatalf("expected one envelope, got %d", len(envelopes))
	}

	ciphertext, err := base64.StdEncoding.DecodeString(envelopes[0].Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}

	plaintext, ok := box.OpenAnonymous(nil, ciphertext, publicKey, privateKey)
	if !ok {
		t.Fatal("ciphertext was not opened by recipient key")
	}
	if string(plaintext) != "hello" {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}
}

func TestRegisterPublicKeyRejectsInvalidKey(t *testing.T) {
	svc := NewService(&fakeKeyRepository{keys: map[string]*PublicKey{}})

	if _, err := svc.RegisterPublicKey(context.Background(), "user1", "not-base64"); err == nil {
		t.Fatal("expected invalid key error")
	}
}
