package did

type DIDDocument struct {
	Context            []string               `json:"@context"`
	ID                 string                 `json:"id"`
	VerificationMethod []VerificationMethod   `json:"verificationMethod"`
	Authentication     []string               `json:"authentication"`
	AssertionMethod    []string               `json:"assertionMethod"`
	CapabilityInv      []string               `json:"capabilityInvocation"`
	CapabilityDel      []string               `json:"capabilityDelegation"`
	Service            []Service              `json:"service"`
}

type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

func Build(did string, rootPubMultibase string, services map[string]string, deviceKeys map[string]string) DIDDocument {
	vm := []VerificationMethod{
		{
			ID:                 did + "#root",
			Type:               "Ed25519VerificationKey2020",
			Controller:         did,
			PublicKeyMultibase: rootPubMultibase,
		},
	}

	// optional device keys as additional verification methods
	for keyID, pub := range deviceKeys {
		vm = append(vm, VerificationMethod{
			ID:                 did + "#" + keyID,
			Type:               "Ed25519VerificationKey2020",
			Controller:         did,
			PublicKeyMultibase: pub,
		})
	}

	svc := []Service{}
	if v := services["pod"]; v != "" {
		svc = append(svc, Service{ID: did + "#pod", Type: "SolidPod", ServiceEndpoint: v})
	}
	if v := services["profile"]; v != "" {
		svc = append(svc, Service{ID: did + "#profile", Type: "GreyThingProfile", ServiceEndpoint: v})
	}
	if v := services["events"]; v != "" {
		svc = append(svc, Service{ID: did + "#events", Type: "GreyThingEventStream", ServiceEndpoint: v})
	}

	return DIDDocument{
		Context:            []string{"https://www.w3.org/ns/did/v1"},
		ID:                 did,
		VerificationMethod: vm,
		Authentication:     []string{did + "#root"},
		AssertionMethod:    []string{did + "#root"},
		CapabilityInv:      []string{did + "#root"},
		CapabilityDel:      []string{did + "#root"},
		Service:            svc,
	}
}
