package management

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/JoshFinlayAU/cgdns/internal/control"
)

// User is a human operator: a WebUI login, as opposed to the API tokens a
// provisioning system uses.
//
// Humans and machines get different treatment on purpose. An API token is 256
// bits of randomness, so a plain hash is enough — there is no dictionary to
// attack. A password is whatever a person chose, so it needs a slow KDF and a
// second factor behind it.
type User struct {
	Name string `json:"name"`
	// Hash is the argon2id encoding, salt and parameters included.
	Hash   string  `json:"hash"`
	Scopes []Scope `json:"scopes"`

	// TOTPSecret is the RFC 6238 shared secret, base32 as authenticator apps
	// expect it. It is empty until enrolment completes.
	//
	// It is stored as the secret rather than a hash because verifying a code
	// requires computing it, which cannot be done from a digest. That is the
	// same concession every TOTP implementation makes; what protects it here
	// is the store's file mode and the mutually authenticated link it
	// replicates over, not the encoding.
	TOTPSecret string `json:"totp_secret,omitempty"`
	// TOTPConfirmed records that the operator proved they can generate codes.
	// Until then the secret exists but does not gate anything, so a failed
	// enrolment cannot lock someone out.
	TOTPConfirmed bool `json:"totp_confirmed,omitempty"`

	Disabled bool      `json:"disabled,omitempty"`
	Created  time.Time `json:"created"`
	// LastLogin is advisory; it is not used for any decision.
	LastLogin time.Time `json:"last_login,omitempty"`
}

// argon2id parameters.
//
// Deliberately costly: this runs once per login attempt, where a tenth of a
// second is invisible to an operator and ruinous to someone working through a
// password list.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrUserNotFound means no such user exists.
var ErrUserNotFound = errors.New("management: user not found")

// ErrBadCredentials is returned for any failed login.
//
// One error for every cause on purpose: telling a caller whether the username
// existed, the password was wrong, or the code was wrong hands them a way to
// enumerate operators.
var ErrBadCredentials = errors.New("management: invalid credentials")

// ErrTOTPRequired means the password was right but a code is still needed.
var ErrTOTPRequired = errors.New("management: a TOTP code is required")

// HashPassword derives an argon2id hash with a fresh salt.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		// Short enough to brute force whatever the KDF costs.
		return "", errors.New("management: a password must be at least 12 characters")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("management: generating salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against an encoded hash.
//
// The parameters come from the hash rather than from the constants above, so
// raising the cost later does not lock out everyone hashed under the old
// settings.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewTOTPSecret generates a shared secret for an authenticator app.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, 20) // 160 bits, per RFC 4226 §4
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("management: generating TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPURI is the otpauth:// URI an authenticator app scans.
func TOTPURI(issuer, user, secret string) string {
	label := issuer + ":" + user
	return "otpauth://totp/" + urlEscape(label) +
		"?secret=" + secret +
		"&issuer=" + urlEscape(issuer) +
		"&algorithm=SHA1&digits=6&period=30"
}

// urlEscape percent-encodes the few characters that matter in a TOTP label.
func urlEscape(s string) string {
	r := strings.NewReplacer(" ", "%20", ":", "%3A", "/", "%2F", "?", "%3F", "#", "%23", "&", "%26")
	return r.Replace(s)
}

// totpStep is the RFC 6238 time step.
const totpStep = 30 * time.Second

// totpSkew is how many steps either side of now are accepted.
//
// One step covers ordinary clock drift between a phone and a server. Widening
// it makes a stolen code useful for longer, which is the thing TOTP exists to
// limit.
const totpSkew = 1

// VerifyTOTP checks a code against a secret at the given time.
func VerifyTOTP(secret, code string, now time.Time) bool {
	if secret == "" || len(code) != 6 {
		return false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return false
	}

	counter := now.Unix() / int64(totpStep.Seconds())
	ok := false
	for skew := -totpSkew; skew <= totpSkew; skew++ {
		// Every candidate is computed and compared, with no early exit, so the
		// time taken does not reveal which step matched.
		if subtle.ConstantTimeCompare([]byte(hotp(key, counter+int64(skew))), []byte(code)) == 1 {
			ok = true
		}
	}
	return ok
}

// hotp computes the RFC 4226 code for one counter value.
func hotp(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

// LoadUser reads one user from the store.
func LoadUser(store *control.Store, name string) (User, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, r := range store.Records() {
		if r.Kind != control.KindUser || r.Key != name {
			continue
		}
		var u User
		if err := json.Unmarshal(r.Payload, &u); err != nil {
			return User{}, fmt.Errorf("management: decoding user %s: %w", name, err)
		}
		return u, nil
	}
	return User{}, ErrUserNotFound
}

// ListUsers returns every user, without hashes or TOTP secrets.
func ListUsers(store *control.Store) ([]User, error) {
	var out []User
	for _, r := range store.Records() {
		if r.Kind != control.KindUser {
			continue
		}
		var u User
		if err := json.Unmarshal(r.Payload, &u); err != nil {
			return nil, fmt.Errorf("management: decoding user %s: %w", r.Key, err)
		}
		u.Hash = ""
		u.TOTPSecret = ""
		out = append(out, u)
	}
	return out, nil
}

// SaveUser writes a user, replicating them to the sibling.
func SaveUser(store *control.Store, u User) error {
	u.Name = strings.ToLower(strings.TrimSpace(u.Name))
	if u.Name == "" {
		return errors.New("management: a user needs a name")
	}
	if len(u.Scopes) == 0 {
		return errors.New("management: a user needs at least one scope")
	}
	for _, s := range u.Scopes {
		if !s.Valid() {
			return fmt.Errorf("management: unknown scope %q", s)
		}
	}
	if _, err := store.Put(control.KindUser, u.Name, u); err != nil {
		return fmt.Errorf("management: storing user %s: %w", u.Name, err)
	}
	return nil
}

// DeleteUser removes a user. The tombstone is what stops the sibling
// resurrecting them on rejoin.
func DeleteUser(store *control.Store, name string) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if _, err := LoadUser(store, name); err != nil {
		return err
	}
	if _, err := store.Delete(control.KindUser, name); err != nil {
		return fmt.Errorf("management: deleting user %s: %w", name, err)
	}
	return nil
}

// Authenticate checks a login.
//
// A missing user is still run through a password verification against a dummy
// hash, so the time taken does not reveal whether the account exists.
func Authenticate(store *control.Store, name, password, code string, now time.Time) (User, error) {
	u, err := LoadUser(store, name)
	if err != nil {
		VerifyPassword(dummyHash, password)
		return User{}, ErrBadCredentials
	}
	if u.Disabled {
		VerifyPassword(dummyHash, password)
		return User{}, ErrBadCredentials
	}
	if !VerifyPassword(u.Hash, password) {
		return User{}, ErrBadCredentials
	}

	// The second factor gates a login only once the operator has proved they
	// can generate codes. A half-finished enrolment must not lock them out.
	if u.TOTPConfirmed {
		if code == "" {
			return User{}, ErrTOTPRequired
		}
		if !VerifyTOTP(u.TOTPSecret, code, now) {
			return User{}, ErrBadCredentials
		}
	}
	return u, nil
}

// dummyHash is a real argon2id hash of a value nobody uses, so verifying
// against it costs the same as verifying a genuine one.
var dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$" +
	base64.RawStdEncoding.EncodeToString(make([]byte, argonSaltLen)) + "$" +
	base64.RawStdEncoding.EncodeToString(make([]byte, argonKeyLen))

// Allows reports whether the user holds the scope.
func (u User) Allows(want Scope) bool {
	if u.Disabled {
		return false
	}
	for _, s := range u.Scopes {
		if s.implies(want) {
			return true
		}
	}
	return false
}

// HasUsers reports whether any operator account exists.
func HasUsers(store *control.Store) bool {
	for _, r := range store.Records() {
		if r.Kind == control.KindUser {
			return true
		}
	}
	return false
}

// parseScopeList turns a comma-separated list into scopes.
func parseScopeList(csv string) []Scope {
	var out []Scope
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, Scope(s))
		}
	}
	return out
}

// digitsOnly reports whether s is all digits, used to sanity-check a TOTP code
// before spending an HMAC on it.
func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.Atoi(s)
	return err == nil
}
