package app

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const captchaTTL = 5 * time.Minute

type captchaChallenge struct {
	Answer    string    `json:"answer"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleCaptcha(w http.ResponseWriter, _ *http.Request) {
	id, question, expiresAt, err := s.auth.createCaptcha()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"captcha_id": id,
		"question":   question,
		"expires_at": expiresAt,
	})
}

func (m *authManager) createCaptcha() (string, string, time.Time, error) {
	left, err := randomCaptchaInt(2, 9)
	if err != nil {
		return "", "", time.Time{}, err
	}
	right, err := randomCaptchaInt(2, 9)
	if err != nil {
		return "", "", time.Time{}, err
	}
	id, err := randomToken()
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt := time.Now().Add(captchaTTL).UTC()
	challenge := captchaChallenge{Answer: fmt.Sprintf("%d", left+right), ExpiresAt: expiresAt}
	if err := m.pruneAuthRuntimeStates(captchaChallengeCollection); err != nil {
		return "", "", time.Time{}, err
	}
	if err := m.persistAuthRuntimeState(captchaChallengeCollection, id, challenge, expiresAt); err != nil {
		return "", "", time.Time{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneCaptchasLocked(time.Now().UTC())
	m.captchas[id] = challenge
	return id, fmt.Sprintf("%d + %d = ?", left, right), expiresAt, nil
}

func (s *Server) verifyCaptcha(id, answer string) (bool, error) {
	if !s.captchaRequired() {
		return true, nil
	}
	return s.auth.verifyCaptcha(id, answer)
}

func (m *authManager) verifyCaptcha(id, answer string) (bool, error) {
	id = strings.TrimSpace(id)
	answer = strings.TrimSpace(answer)
	if id == "" || answer == "" {
		return false, nil
	}
	now := time.Now().UTC()
	var challenge captchaChallenge
	ok, err := m.consumeAuthRuntimeState(captchaChallengeCollection, id, &challenge)
	if m.store == nil {
		m.mu.Lock()
		m.pruneCaptchasLocked(now)
		challenge, ok = m.captchas[id]
		delete(m.captchas, id)
		m.mu.Unlock()
	}
	m.mu.Lock()
	delete(m.captchas, id)
	m.mu.Unlock()
	if err != nil || !ok {
		return false, err
	}
	return now.Before(challenge.ExpiresAt) && strings.EqualFold(answer, challenge.Answer), nil
}

func (m *authManager) pruneCaptchasLocked(now time.Time) {
	for id, challenge := range m.captchas {
		if now.After(challenge.ExpiresAt) {
			delete(m.captchas, id)
		}
	}
}

func (s *Server) captchaRequired() bool {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return false
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		itemType := strings.ToLower(strings.TrimSpace(item.Type))
		if itemType != "security" && itemType != "identity" && itemType != "login" && itemType != "captcha" {
			continue
		}
		for _, key := range []string{"captcha_enabled", "login_captcha", "enable_captcha", "captcha", "require_captcha"} {
			if metadataBoolForMFA(item.Metadata[key]) {
				return true
			}
		}
	}
	return false
}

func randomCaptchaInt(min, max int64) (int64, error) {
	if max < min {
		max = min
	}
	value, err := rand.Int(rand.Reader, big.NewInt(max-min+1))
	if err != nil {
		return 0, err
	}
	return min + value.Int64(), nil
}
