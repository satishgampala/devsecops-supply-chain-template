package signingpolicy

const SchemaVersion = "1.0"

type Policy struct {
	SchemaVersion       string         `json:"schemaVersion"`
	Issuer              string         `json:"issuer"`
	CertificateIdentity string         `json:"certificateIdentity"`
	Repository          string         `json:"repository"`
	WorkflowName        string         `json:"workflowName"`
	WorkflowRef         string         `json:"workflowRef"`
	AllowedTriggers     []string       `json:"allowedTriggers"`
	RequiredArtifacts   []ArtifactRule `json:"requiredArtifacts"`
}

type ArtifactRule struct {
	Role   string `json:"role"`
	Path   string `json:"path"`
	Bundle string `json:"bundle"`
}

type Observation struct {
	SchemaVersion             string                `json:"schemaVersion"`
	Issuer                    string                `json:"issuer"`
	CertificateIdentity       string                `json:"certificateIdentity"`
	Repository                string                `json:"repository"`
	WorkflowName              string                `json:"workflowName"`
	WorkflowRef               string                `json:"workflowRef"`
	WorkflowSHA               string                `json:"workflowSHA"`
	WorkflowTrigger           string                `json:"workflowTrigger"`
	CryptographicVerification bool                  `json:"cryptographicVerification"`
	TransparencyLogVerified   bool                  `json:"transparencyLogVerified"`
	EmbeddedSCTVerified       bool                  `json:"embeddedSCTVerified"`
	Artifacts                 []ArtifactObservation `json:"artifacts"`
}

type ArtifactObservation struct {
	Role         string `json:"role"`
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Bundle       string `json:"bundle"`
	BundleSHA256 string `json:"bundleSHA256"`
	Verified     bool   `json:"verified"`
}

type Decision struct {
	SchemaVersion string                `json:"schemaVersion"`
	Eligible      bool                  `json:"eligible"`
	ReasonCodes   []string              `json:"reasonCodes"`
	Identity      IdentitySummary       `json:"identity"`
	Artifacts     []ArtifactObservation `json:"artifacts"`
}

type IdentitySummary struct {
	Issuer              string `json:"issuer"`
	CertificateIdentity string `json:"certificateIdentity"`
	Repository          string `json:"repository"`
	WorkflowName        string `json:"workflowName"`
	WorkflowRef         string `json:"workflowRef"`
	WorkflowSHA         string `json:"workflowSHA"`
	WorkflowTrigger     string `json:"workflowTrigger"`
}
