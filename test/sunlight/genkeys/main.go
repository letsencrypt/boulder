// genkeys generates the seed the sunlight mirrors share and the throwaway CT
// log's accepted roots file, and writes the mirror log list. It also derives
// each mirror cosigner's public key the way cmd/sunlight derives the private
// key, and writes them in the form of Chrome's cosigners.json and
// cosigners.pem for the mtpublisher config.
// https://github.com/FiloSottile/sunlight/blob/v0.10.2/cmd/sunlight/sunlight.go#L1028-L1040
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

// mirror describes a sunlight mirror of the dev stack.
type mirror struct {
	friendlyName string
	// id is the mirror's cosigner ID, whose oid form must match the mirrorname
	// in the mirror's sunlight config.
	id string
	// submissionPrefix and monitoringPrefix are where the mtpublisher reaches
	// the mirror, matching its sunlight config and docker-compose.yml.
	submissionPrefix string
	monitoringPrefix string
}

// mirrors are the dev stack's mirrors, one per sunlight config in
// test/sunlight. They derive distinct keys from the shared seed by name.
var mirrors = []mirror{
	{
		friendlyName:     "concave",
		id:               "32473.9",
		submissionPrefix: "http://boulder-sunlight:4700",
		monitoringPrefix: "http://boulder-seaweedfs:8333/boulder-sunlight/mirror",
	},
	{
		friendlyName:     "convex",
		id:               "32473.10",
		submissionPrefix: "http://boulder-sunlight2:4700",
		monitoringPrefix: "http://boulder-seaweedfs:8333/boulder-sunlight2/mirror",
	},
}

// name returns the mirror's cosigner name, the HKDF info cmd/sunlight derives
// its key with.
func (m mirror) name() string {
	return "oid/1.3.6.1.4.1." + m.id
}

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

// cosignerFiles writes cosigners.json and cosigners.pem under dir, listing
// each mirror as a Usable mirror in the PUBLICLY_TRUSTED realm with
// the key it derives from seed.
func cosignerFiles(dir string, seed []byte) error {
	type stateChange struct {
		State      string `json:"state"`
		StateStart string `json:"state_start"`
	}
	type operatorChange struct {
		Name          string `json:"name"`
		OperatorStart string `json:"operator_start"`
	}
	type signer struct {
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
		Mirrors   []signer `json:"mirrors"`
	}{
		Timestamp: "2026-01-01T00:00:00Z",
		Version:   "0.0.1",
	}
	var cosignersPEM []byte
	for _, m := range mirrors {
		secret, err := hkdf.Key(sha256.New, seed, []byte("sunlight ML-DSA-44 mirror key"), m.name(), 32)
		if err != nil {
			return err
		}
		key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), secret)
		if err != nil {
			return err
		}
		spki, err := x509.MarshalPKIXPublicKey(key.PublicKey())
		if err != nil {
			return err
		}
		keySHA256 := fmt.Sprintf("%x", sha256.Sum256(spki))
		list.Mirrors = append(list.Mirrors, signer{
			FriendlyName:     m.friendlyName,
			BaseID:           m.id,
			StateHistory:     []stateChange{{State: "USABLE", StateStart: "2026-01-01T00:00:00Z"}},
			OperatorHistory:  []operatorChange{{Name: "Boulder", OperatorStart: "2026-01-01T00:00:00Z"}},
			BaseURL:          m.monitoringPrefix,
			SubmissionPrefix: m.submissionPrefix,
			Type:             "MIRROR",
			Realm:            "PUBLICLY_TRUSTED",
			KeySHA256:        keySHA256,
		})
		cosignersPEM = append(cosignersPEM, []byte("# "+keySHA256+"\n")...)
		cosignersPEM = append(cosignersPEM, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})...)
	}
	cosignersJSON, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(path.Join(dir, "cosigners.json"), append(cosignersJSON, '\n'), 0644)
	if err != nil {
		return err
	}
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

	err = cosignerFiles(*outputDir, seed)
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
