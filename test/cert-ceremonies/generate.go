package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"

	"github.com/letsencrypt/boulder/cmd"
)

func createSlot(label string) (string, error) {
	output, err := exec.Command("softhsm2-util", "--init-token", "--free", "--label", label, "--pin", "1234", "--so-pin", "5678").CombinedOutput()
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`to slot (\d+)`)
	matches := re.FindSubmatch(output)
	if len(matches) != 2 {
		return "", errors.New("unexpected number of slot matches")
	}
	return string(matches[1]), nil
}

func genKey(path string, inSlot string) (string, error) {
	tmpPath, err := rewriteConfig(path, map[string]string{"$slotID$": inSlot})
	if err != nil {
		return "", err
	}
	output, err := exec.Command("bin/ceremony", "-config", tmpPath).CombinedOutput()
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`and ID ([a-z0-9]{8})`)
	matches := re.FindSubmatch(output)
	if len(matches) != 2 {
		return "", errors.New("unexpected number of key ID matches")
	}
	return string(matches[1]), nil
}

func rewriteConfig(path string, rewrites map[string]string) (string, error) {
	config, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	tmp, err := ioutil.TempFile(os.TempDir(), "intermediate")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	for replace, with := range rewrites {
		config = bytes.Replace(config, []byte(replace), []byte(with), 1)
	}
	_, err = tmp.Write(config)
	if err != nil {
		return "", err
	}
	return tmp.Name(), nil
}

func genCert(path string) error {
	return exec.Command("bin/ceremony", "-config", path).Run()
}

func main() {
	rootKeySlot, err := createSlot("root signing key (rsa)")
	cmd.FailOnError(err, "failed creating softhsm2 slot for root key")

	rsaRootKeyID, err := genKey("test/cert-ceremonies/root-ceremony-rsa.yaml", rootKeySlot)
	cmd.FailOnError(err, "failed to generate root key + root cert")

	intermediateKeySlot, err := createSlot("intermediate signing key (rsa)")
	cmd.FailOnError(err, "failed to create softhsm2 slot for intermediate key")

	_, err = genKey("test/cert-ceremonies/intermediate-key-ceremony-rsa.yaml", intermediateKeySlot)
	cmd.FailOnError(err, "failed to generate intermediate key")

	tmpRSAIntermediateA, err := rewriteConfig("test/cert-ceremonies/intermediate-ceremony-rsa-a.yaml", map[string]string{
		"$keyID$":  rsaRootKeyID,
		"$slotID$": rootKeySlot,
	})
	cmd.FailOnError(err, "failed to rewrite intermediate cert config with key ID")
	err = genCert(tmpRSAIntermediateA)
	cmd.FailOnError(err, "failed to generate intermediate cert")

	tmpRSAIntermediateB, err := rewriteConfig("test/cert-ceremonies/intermediate-ceremony-rsa-b.yaml", map[string]string{
		"$keyID$":  rsaRootKeyID,
		"$slotID$": rootKeySlot,
	})
	cmd.FailOnError(err, "failed to rewrite intermediate cert config with key ID")
	err = genCert(tmpRSAIntermediateB)
	cmd.FailOnError(err, "failed to generate intermediate cert")
}
