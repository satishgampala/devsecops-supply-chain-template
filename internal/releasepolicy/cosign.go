package releasepolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

var (
	ErrSignatureVerification = errors.New("signature verification failed")
	ErrVerificationTool      = errors.New("verification tool unavailable")
)

type SignatureRequest struct {
	ArtifactPath        string
	BundlePath          string
	CertificateIdentity string
	Issuer              string
	WorkflowName        string
	Repository          string
	WorkflowRef         string
	WorkflowSHA         string
	WorkflowTrigger     string
}

type SignatureVerifier interface {
	Version(context.Context) (string, error)
	Verify(context.Context, SignatureRequest) error
}

type CosignVerifier struct {
	Binary string
}

func (verifier CosignVerifier) Version(ctx context.Context) (string, error) {
	output, err := verifier.run(ctx, "version")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrVerificationTool, err)
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "GitVersion:" {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("%w: Cosign version was not reported", ErrVerificationTool)
}

func (verifier CosignVerifier) Verify(ctx context.Context, request SignatureRequest) error {
	_, err := verifier.run(ctx,
		"verify-blob",
		"--bundle", request.BundlePath,
		"--certificate-identity", request.CertificateIdentity,
		"--certificate-oidc-issuer", request.Issuer,
		"--certificate-github-workflow-name", request.WorkflowName,
		"--certificate-github-workflow-repository", request.Repository,
		"--certificate-github-workflow-ref", request.WorkflowRef,
		"--certificate-github-workflow-sha", request.WorkflowSHA,
		"--certificate-github-workflow-trigger", request.WorkflowTrigger,
		request.ArtifactPath,
	)
	if err != nil {
		return fmt.Errorf("%w", ErrSignatureVerification)
	}
	return nil
}

func (verifier CosignVerifier) run(ctx context.Context, arguments ...string) (string, error) {
	binary := strings.TrimSpace(verifier.Binary)
	if binary == "" {
		binary = "cosign"
	}
	path, err := exec.LookPath(binary)
	if err != nil {
		return "", err
	}
	commandContext, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(commandContext, path, arguments...)
	var output bytes.Buffer
	limited := &cappedWriter{buffer: &output, remaining: 64 << 10}
	command.Stdout = limited
	command.Stderr = limited
	if err := command.Run(); err != nil {
		return output.String(), err
	}
	return output.String(), nil
}

type cappedWriter struct {
	buffer    *bytes.Buffer
	remaining int
}

func (writer *cappedWriter) Write(content []byte) (int, error) {
	originalLength := len(content)
	if writer.remaining > 0 {
		length := len(content)
		if length > writer.remaining {
			length = writer.remaining
		}
		if _, err := writer.buffer.Write(content[:length]); err != nil {
			return 0, err
		}
		writer.remaining -= length
	}
	return originalLength, nil
}
