package did

import "sort"

type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`

	Authentication  []string `json:"authentication"`
	AssertionMethod []string `json:"assertionMethod"`

	CapabilityInv []string `json:"capabilityInvocation"`
	CapabilityDel []string `json:"capabilityDelegation"`

	// NEW: key agreement references for encryption keys (e.g. X25519)
	KeyAgreement []string `json:"keyAgreement,omitempty"`

	Service []Service `json:"service"`
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

func Build(
	did string,
	rootPubMultibase string,
	services map[string]string,
	deviceKeys map[string]string,
	deviceXKeys map[string]string,
) DIDDocument {
	vm := []VerificationMethod{
		{
			ID:                 did + "#root",
			Type:               "Ed25519VerificationKey2020",
			Controller:         did,
			PublicKeyMultibase: rootPubMultibase,
		},
	}

	// Deterministic ordering
	addEd := make([]string, 0, len(deviceKeys))
	for keyID := range deviceKeys {
		addEd = append(addEd, keyID)
	}
	sort.Strings(addEd)

	for _, keyID := range addEd {
		pub := deviceKeys[keyID]
		vm = append(vm, VerificationMethod{
			ID:                 did + "#" + keyID,
			Type:               "Ed25519VerificationKey2020",
			Controller:         did,
			PublicKeyMultibase: pub,
		})
	}

	// X25519 device encryption keys
	keyAgreement := []string{}
	addX := make([]string, 0, len(deviceXKeys))
	for keyID := range deviceXKeys {
		addX = append(addX, keyID)
	}
	sort.Strings(addX)

	for _, keyID := range addX {
		pub := deviceXKeys[keyID]
		vmID := did + "#" + keyID
		vm = append(vm, VerificationMethod{
			ID:                 vmID,
			Type:               "X25519KeyAgreementKey2020",
			Controller:         did,
			PublicKeyMultibase: pub,
		})
		keyAgreement = append(keyAgreement, vmID)
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

	doc := DIDDocument{
		Context:            []string{"https://www.w3.org/ns/did/v1"},
		ID:                 did,
		VerificationMethod: vm,
		Authentication:     []string{did + "#root"},
		AssertionMethod:    []string{did + "#root"},
		CapabilityInv:      []string{did + "#root"},
		CapabilityDel:      []string{did + "#root"},
		Service:            svc,
	}
	if len(keyAgreement) > 0 {
		doc.KeyAgreement = keyAgreement
	}
	return doc
}
