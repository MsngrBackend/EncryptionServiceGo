package encryption

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/nacl/box"
)

const (
	Algorithm = "nacl-box-x25519-xsalsa20-poly1305-sealed-v1"

	rawPublicKeySize = 32
)

var (
	ErrInvalidInput = errors.New("invalid input")
	ErrNotFound     = errors.New("public key not found")
)

type Recipient struct {
	UserID    string `json:"user_id"`
	PublicKey string `json:"public_key,omitempty"`
}

type Envelope struct {
	UserID     string `json:"user_id"`
	Algorithm  string `json:"algorithm"`
	Ciphertext string `json:"ciphertext"`
}

type keyRepository interface {
	UpsertPublicKey(ctx context.Context, userID, publicKey string) (*PublicKey, error)
	GetPublicKey(ctx context.Context, userID string) (*PublicKey, error)
	LookupPublicKeys(ctx context.Context, userIDs []string) ([]*PublicKey, error)
}

type Service struct {
	repo keyRepository
}

func NewService(repo keyRepository) *Service {
	return &Service{repo: repo}
}

func (s *Service) RegisterPublicKey(ctx context.Context, userID, publicKey string) (*PublicKey, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, invalidInput("user_id is required")
	}

	normalized, err := normalizePublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return s.repo.UpsertPublicKey(ctx, userID, normalized)
}

func (s *Service) GetPublicKey(ctx context.Context, userID string) (*PublicKey, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, invalidInput("user_id is required")
	}

	key, err := s.repo.GetPublicKey(ctx, userID)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, userID)
	}
	return key, nil
}

func (s *Service) LookupPublicKeys(ctx context.Context, userIDs []string) ([]*PublicKey, error) {
	if len(userIDs) == 0 {
		return nil, invalidInput("user_ids is required")
	}

	seen := make(map[string]struct{}, len(userIDs))
	normalized := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, invalidInput("user_ids cannot contain empty values")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		normalized = append(normalized, id)
	}

	return s.repo.LookupPublicKeys(ctx, normalized)
}

func (s *Service) EncryptMessage(ctx context.Context, content string, recipients []Recipient) ([]Envelope, error) {
	if content == "" {
		return nil, invalidInput("content is required")
	}
	if len(recipients) == 0 {
		return nil, invalidInput("recipients is required")
	}

	envelopes := make([]Envelope, 0, len(recipients))
	seen := make(map[string]struct{}, len(recipients))
	for _, recipient := range recipients {
		userID := strings.TrimSpace(recipient.UserID)
		if userID == "" {
			return nil, invalidInput("recipient user_id is required")
		}
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}

		publicKey := strings.TrimSpace(recipient.PublicKey)
		if publicKey == "" {
			key, err := s.GetPublicKey(ctx, userID)
			if err != nil {
				return nil, err
			}
			publicKey = key.PublicKey
		}

		decoded, err := decodePublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid public_key for %s", ErrInvalidInput, userID)
		}

		sealed, err := box.SealAnonymous(nil, []byte(content), decoded, rand.Reader)
		if err != nil {
			return nil, err
		}

		envelopes = append(envelopes, Envelope{
			UserID:     userID,
			Algorithm:  Algorithm,
			Ciphertext: base64.StdEncoding.EncodeToString(sealed),
		})
	}

	return envelopes, nil
}

func normalizePublicKey(publicKey string) (string, error) {
	decoded, err := decodePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(decoded[:]), nil
}

func decodePublicKey(publicKey string) (*[rawPublicKeySize]byte, error) {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return nil, invalidInput("public_key is required")
	}

	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: public_key must be base64", ErrInvalidInput)
	}
	if len(raw) != rawPublicKeySize {
		return nil, fmt.Errorf("%w: public_key must decode to 32 bytes", ErrInvalidInput)
	}

	var key [rawPublicKeySize]byte
	copy(key[:], raw)
	return &key, nil
}

func invalidInput(message string) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, message)
}
