package management

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHashPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash is not argon2id: %q", hash)
	}
	if strings.Contains(hash, "correct horse") {
		t.Fatal("the hash contains the password")
	}
	if !VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("the correct password was rejected")
	}
	if VerifyPassword(hash, "Correct horse battery staple") {
		t.Fatal("a wrong password was accepted")
	}
}

// Every hash must carry its own salt, or identical passwords would be
// identifiable as identical from the store alone.
func TestHashPassword_SaltsEachHash(t *testing.T) {
	a, err := HashPassword("the same password twice")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("the same password twice")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical, so the salt is not being used")
	}
	if !VerifyPassword(a, "the same password twice") || !VerifyPassword(b, "the same password twice") {
		t.Fatal("a salted hash failed to verify")
	}
}

// A short password is brute-forceable whatever the KDF costs.
func TestHashPassword_RejectsShortPasswords(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("a five-character password was accepted")
	}
	if _, err := HashPassword("exactlytwelve"); err != nil {
		t.Fatalf("a long enough password was rejected: %v", err)
	}
}

// Verification reads the cost from the hash, so raising it later must not lock
// out anyone hashed under the old settings.
func TestVerifyPassword_HonoursTheEmbeddedParameters(t *testing.T) {
	hash, err := HashPassword("a perfectly fine password")
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite the parameters to something else and confirm verification fails
	// rather than silently ignoring them.
	tampered := strings.Replace(hash, "m=65536,t=3,p=4", "m=32768,t=2,p=4", 1)
	if VerifyPassword(tampered, "a perfectly fine password") {
		t.Fatal("verification ignored the parameters in the hash")
	}
}

func TestVerifyPassword_RejectsMalformedHashes(t *testing.T) {
	for _, tc := range []string{
		"", "not-a-hash", "$argon2id$", "$bcrypt$v=19$m=1,t=1,p=1$aaaa$bbbb",
		"$argon2id$v=99$m=65536,t=3,p=4$aaaa$bbbb",
		"$argon2id$v=19$garbage$aaaa$bbbb",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!!$bbbb",
	} {
		if VerifyPassword(tc, "anything") {
			t.Fatalf("malformed hash %q was accepted", tc)
		}
	}
}

// RFC 6238 test vectors, using the published SHA-1 seed "12345678901234567890".
func TestVerifyTOTP_RFC6238Vectors(t *testing.T) {
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte("12345678901234567890"))

	for _, tc := range []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	} {
		at := time.Unix(tc.unix, 0)
		if !VerifyTOTP(seed, tc.code, at) {
			t.Fatalf("RFC 6238 vector at t=%d: code %s was rejected", tc.unix, tc.code)
		}
	}
}

// A code from a step outside the accepted window must fail, or TOTP would stop
// bounding how long a stolen code stays useful.
func TestVerifyTOTP_WindowIsNarrow(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1700000000, 0)
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	counter := base.Unix() / 30

	if !VerifyTOTP(secret, hotp(key, counter), base) {
		t.Fatal("the current code was rejected")
	}
	// One step either side is accepted, for clock drift.
	for _, skew := range []int64{-1, 1} {
		if !VerifyTOTP(secret, hotp(key, counter+skew), base) {
			t.Fatalf("a code one step away (%d) was rejected", skew)
		}
	}
	// Two steps away is not.
	for _, skew := range []int64{-2, 2, 10} {
		if VerifyTOTP(secret, hotp(key, counter+skew), base) {
			t.Fatalf("a code %d steps away was accepted", skew)
		}
	}
}

func TestVerifyTOTP_RejectsRubbish(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, code := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if code == "000000" {
			continue // could legitimately be the current code
		}
		if VerifyTOTP(secret, code, now) {
			t.Fatalf("code %q was accepted", code)
		}
	}
	if VerifyTOTP("", "123456", now) {
		t.Fatal("an empty secret accepted a code")
	}
	if VerifyTOTP("not-base32!!", "123456", now) {
		t.Fatal("an unparseable secret accepted a code")
	}
}

func TestNewTOTPSecret_IsUsableByAnAuthenticator(t *testing.T) {
	seen := map[string]bool{}
	for range 20 {
		s, err := NewTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		if seen[s] {
			t.Fatal("two secrets collided")
		}
		seen[s] = true

		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
		if err != nil {
			t.Fatalf("secret is not decodable base32: %v", err)
		}
		if len(raw) != 20 {
			t.Fatalf("secret is %d bytes, want the RFC 4226 minimum of 20", len(raw))
		}
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("cgdns ns1", "jo:sh", "ABCDEF")
	for _, want := range []string{"otpauth://totp/", "secret=ABCDEF", "issuer=cgdns%20ns1", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("URI %q is missing %q", uri, want)
		}
	}
	if strings.Contains(uri, "jo:sh") {
		t.Fatalf("the label was not escaped: %q", uri)
	}
}

func TestAuthenticate(t *testing.T) {
	store := testStore(t)
	hash, err := HashPassword("a perfectly fine password")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveUser(store, User{Name: "jo", Hash: hash, Scopes: []Scope{ScopeAdmin}, TOTPSecret: secret}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// Enrolment is not confirmed, so a code is not yet required: a half-done
	// enrolment must not lock the operator out.
	if _, err := Authenticate(store, "jo", "a perfectly fine password", "", now); err != nil {
		t.Fatalf("login before TOTP confirmation failed: %v", err)
	}

	// Confirm it, and the code becomes mandatory.
	u, _ := LoadUser(store, "jo")
	u.TOTPConfirmed = true
	if err := SaveUser(store, u); err != nil {
		t.Fatal(err)
	}

	if _, err := Authenticate(store, "jo", "a perfectly fine password", "", now); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("got %v, want ErrTOTPRequired", err)
	}
	if _, err := Authenticate(store, "jo", "a perfectly fine password", "000001", now); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("a wrong code got %v, want ErrBadCredentials", err)
	}

	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	code := hotp(key, now.Unix()/30)
	if _, err := Authenticate(store, "jo", "a perfectly fine password", code, now); err != nil {
		t.Fatalf("a correct password and code failed: %v", err)
	}
}

// Every failure must look the same, or a caller can enumerate operators.
func TestAuthenticate_DoesNotRevealWhichPartFailed(t *testing.T) {
	store := testStore(t)
	hash, err := HashPassword("a perfectly fine password")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveUser(store, User{Name: "jo", Hash: hash, Scopes: []Scope{ScopeRead}}); err != nil {
		t.Fatal(err)
	}

	_, wrongUser := Authenticate(store, "nobody", "a perfectly fine password", "", time.Now())
	_, wrongPass := Authenticate(store, "jo", "the wrong password entirely", "", time.Now())

	if !errors.Is(wrongUser, ErrBadCredentials) || !errors.Is(wrongPass, ErrBadCredentials) {
		t.Fatalf("unknown user: %v, wrong password: %v", wrongUser, wrongPass)
	}
	if wrongUser.Error() != wrongPass.Error() {
		t.Fatalf("the two failures differ: %q vs %q", wrongUser, wrongPass)
	}
}

func TestAuthenticate_RejectsADisabledUser(t *testing.T) {
	store := testStore(t)
	hash, err := HashPassword("a perfectly fine password")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveUser(store, User{Name: "jo", Hash: hash, Scopes: []Scope{ScopeAdmin}, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Authenticate(store, "jo", "a perfectly fine password", "", time.Now()); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("a disabled user logged in: %v", err)
	}
}

func TestUserLifecycle(t *testing.T) {
	store := testStore(t)
	hash, err := HashPassword("a perfectly fine password")
	if err != nil {
		t.Fatal(err)
	}

	// Names are case-insensitive, so "Jo" and "jo" cannot be two accounts.
	if err := SaveUser(store, User{Name: "Jo", Hash: hash, Scopes: []Scope{ScopeWrite}}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUser(store, "jo"); err != nil {
		t.Fatalf("lookup by lowercase name failed: %v", err)
	}
	if _, err := LoadUser(store, "JO"); err != nil {
		t.Fatalf("lookup by uppercase name failed: %v", err)
	}

	users, err := ListUsers(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 {
		t.Fatalf("listed %d users, want 1", len(users))
	}
	if users[0].Hash != "" || users[0].TOTPSecret != "" {
		t.Fatal("the listing disclosed a password hash or TOTP secret")
	}

	if err := DeleteUser(store, "jo"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUser(store, "jo"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got %v, want ErrUserNotFound", err)
	}
	if err := DeleteUser(store, "jo"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("deleting twice got %v", err)
	}
}

func TestSaveUser_Rejects(t *testing.T) {
	store := testStore(t)
	for _, tc := range []struct {
		name string
		u    User
	}{
		{"no name", User{Scopes: []Scope{ScopeRead}}},
		{"blank name", User{Name: "   ", Scopes: []Scope{ScopeRead}}},
		{"no scopes", User{Name: "jo"}},
		{"unknown scope", User{Name: "jo", Scopes: []Scope{Scope("root")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := SaveUser(store, tc.u); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestUser_Allows(t *testing.T) {
	u := User{Name: "jo", Scopes: []Scope{ScopeWrite}}
	if !u.Allows(ScopeRead) || !u.Allows(ScopeWrite) {
		t.Fatal("write should imply read")
	}
	if u.Allows(ScopeAdmin) {
		t.Fatal("write should not imply admin")
	}

	u.Disabled = true
	if u.Allows(ScopeRead) {
		t.Fatal("a disabled user retained a scope")
	}
}
