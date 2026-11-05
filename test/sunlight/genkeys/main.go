// genkeys generates the sunlight witness's seed and the throwaway CT log's
// accepted roots file, and writes the mirror log list. It also derives the
// mirror cosigner's public key the way cmd/sunlight derives the private key,
// and writes it in the form of Chrome's cosigners.json and cosigners.pem for
// the mtpublisher config.
// https://github.com/FiloSottile/sunlight/blob/v0.9.0/cmd/sunlight/sunlight.go#L933-L940
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path"
	"time"

	"github.com/letsencrypt/boulder/trees/issuancelog"
)

// mirrorID is the mirror's cosigner ID, and mirrorName its oid form, which
// must match the mirrorname in test/sunlight/sunlight.yaml.
const mirrorID = "32473.9"
const mirrorName = "oid/1.3.6.1.4.1." + mirrorID

// mirrorSubmissionPrefix and mirrorMonitoringPrefix are where the mtpublisher
// reaches the sunlight mirror, matching test/sunlight/sunlight.yaml and
// docker-compose.yml.
const mirrorSubmissionPrefix = "http://boulder-sunlight:4700"
const mirrorMonitoringPrefix = "http://boulder-seaweedfs:8333/boulder-sunlight/mirror"

// caID and logNumber identify the test MTCA and its issuance log, matching the
// logID in the mtca and mtpublisher configs.
const caID = "44947.4.1"
const logNumber = 3

// cosignatureVKey encodes an ML-DSA-44 cosignature verifier key in the note
// vkey form sunlight's log lists require.
func cosignatureVKey(name string, publicKey *mldsa.PublicKey) string {
	algKey := append([]byte{6}, publicKey.Bytes()...)
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n'})
	h.Write(algKey)
	hash := binary.BigEndian.Uint32(h.Sum(nil)[:4])
	return fmt.Sprintf("%s+%08x+%s", name, hash, base64.StdEncoding.EncodeToString(algKey))
}

// logListFile writes the mirror log list to p, which authorizes the MTCA's log
// to use the sunlight mirror endpoints, carrying the CA cosigner's verifier key
// read from mtcaPublicKeyFile.
func logListFile(p, mtcaPublicKeyFile string) error {
	pemBytes, err := os.ReadFile(mtcaPublicKeyFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return fmt.Errorf("no PEM block in %s", mtcaPublicKeyFile)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	mtcaKey, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("MTCA public key is %T, must be ML-DSA-44", pub)
	}
	logID, err := issuancelog.Config{CAID: caID, LogNumber: logNumber}.Load()
	if err != nil {
		return err
	}
	logList := "logs/v0\nvkey " + cosignatureVKey("oid/1.3.6.1.4.1."+caID, mtcaKey) +
		"\norigin " + logID.Origin() + "\n"
	return os.WriteFile(p, []byte(logList), 0644)
}

// cosignerFiles writes cosigners.json and cosigners.pem under dir, listing the
// sunlight mirror as a Usable mirror in the UNTRUSTED_VALIDATION_ONLY realm
// with the key mirrorSPKI.
func cosignerFiles(dir string, mirrorSPKI []byte) error {
	keySHA256 := fmt.Sprintf("%x", sha256.Sum256(mirrorSPKI))
	type stateChange struct {
		State      string `json:"state"`
		StateStart string `json:"state_start"`
	}
	type operatorChange struct {
		Name          string `json:"name"`
		OperatorStart string `json:"operator_start"`
	}
	type mirror struct {
		FriendlyName     string           `json:"friendly_name"`
		BaseID           string           `json:"base_id"`
		StateHistory     []stateChange    `json:"state_history"`
		OperatorHistory  []operatorChange `json:"operator_history"`
		BaseURL          string           `json:"base_url"`
		SubmissionPrefix string           `json:"submission_prefix"`
		Type             string           `json:"type"`
		Realm            string           `json:"realm"`
		KeySHA256        string           `json:"key_sha256"`
	}
	list := struct {
		Timestamp string   `json:"timestamp"`
		Version   string   `json:"version"`
		Mirrors   []mirror `json:"mirrors"`
	}{
		Timestamp: "2026-01-01T00:00:00Z",
		Version:   "0.0.1",
		Mirrors: []mirror{{
			FriendlyName:     "Boulder Sunlight Test Mirror",
			BaseID:           mirrorID,
			StateHistory:     []stateChange{{State: "USABLE", StateStart: "2026-01-01T00:00:00Z"}},
			OperatorHistory:  []operatorChange{{Name: "Boulder", OperatorStart: "2026-01-01T00:00:00Z"}},
			BaseURL:          mirrorMonitoringPrefix,
			SubmissionPrefix: mirrorSubmissionPrefix,
			Type:             "MIRROR",
			Realm:            "UNTRUSTED_VALIDATION_ONLY",
			KeySHA256:        keySHA256,
		}},
	}
	cosignersJSON, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(path.Join(dir, "cosigners.json"), append(cosignersJSON, '\n'), 0644)
	if err != nil {
		return err
	}
	cosignersPEM := append([]byte("# "+keySHA256+"\n"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mirrorSPKI})...)
	return os.WriteFile(path.Join(dir, "cosigners.pem"), cosignersPEM, 0644)
}

func rootsFile(p string) error {
	_, err := os.Stat(p)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bsunlight ctlog test root"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return err
	}
	rootsFile, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer rootsFile.Close()
	return pem.Encode(rootsFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
}

func seedFile(p string) ([]byte, error) {
	seed, err := os.ReadFile(p)
	if err == nil {
		if len(seed) != 32 {
			return nil, fmt.Errorf("%s is %d bytes, must be exactly 32", p, len(seed))
		}
		return seed, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seed = make([]byte, 32)
	_, err = rand.Read(seed)
	if err != nil {
		return nil, err
	}
	return seed, os.WriteFile(p, seed, 0600)
}

func main2() error {
	outputDir := flag.String("output-dir", "", "Directory to write outputs to")
	mtcaPublicKeyFile := flag.String("mtca-public-key", "", "File with the MTCA's PEM public key, for the mirror log list")
	flag.Parse()

	if *outputDir == "" {
		return errors.New("-output-dir flag required")
	}
	if *mtcaPublicKeyFile == "" {
		return errors.New("-mtca-public-key flag required")
	}

	seed, err := seedFile(path.Join(*outputDir, "seed.bin"))
	if err != nil {
		return err
	}

	mirrorSecret, err := hkdf.Key(sha256.New, seed, []byte("sunlight ML-DSA-44 mirror key"), mirrorName, 32)
	if err != nil {
		return err
	}
	mirrorKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), mirrorSecret)
	if err != nil {
		return err
	}
	mirrorSPKI, err := x509.MarshalPKIXPublicKey(mirrorKey.PublicKey())
	if err != nil {
		return err
	}
	err = cosignerFiles(*outputDir, mirrorSPKI)
	if err != nil {
		return err
	}

	err = rootsFile(path.Join(*outputDir, "ctlog-roots.pem"))
	if err != nil {
		return err
	}

	// generate.sh reruns this program whenever mtc-logs.txt is missing or
	// older than the MTCA public key, so it must be written last. Written
	// any earlier, a partial run would look complete and never be rerun.
	return logListFile(path.Join(*outputDir, "mtc-logs.txt"), *mtcaPublicKeyFile)
}

func main() {
	err := main2()
	if err != nil {
		log.Fatal(err)
	}
}
