package did

import (
	"sort"
	"strings"
)

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

	RecoveryPolicy *RecoveryPolicy `json:"recoveryPolicy,omitempty"`
}

type RecoveryPolicy struct {
	Type        string `json:"type"`
	StorageHead string `json:"storageHead"`
	SetAt       string `json:"setAt"`
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
	recoveryPolicy *RecoveryPolicy,
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
		RecoveryPolicy:     recoveryPolicy,
	}
	if len(keyAgreement) > 0 {
		doc.KeyAgreement = keyAgreement
	}
	return doc
}

// ParseDocument extracts Build() inputs from an existing DID document (round-trip support).
func ParseDocument(doc DIDDocument) (rootPub string, services map[string]string, deviceKeys map[string]string, deviceXKeys map[string]string, recoveryPolicy *RecoveryPolicy) {
	services = make(map[string]string)
	deviceKeys = make(map[string]string)
	deviceXKeys = make(map[string]string)

	for _, vm := range doc.VerificationMethod {
		fragment := vm.ID
		if idx := strings.LastIndex(fragment, "#"); idx >= 0 {
			fragment = fragment[idx+1:]
		}

		if fragment == "root" {
			rootPub = vm.PublicKeyMultibase
			continue
		}

		switch vm.Type {
		case "Ed25519VerificationKey2020":
			deviceKeys[fragment] = vm.PublicKeyMultibase
		case "X25519KeyAgreementKey2020":
			deviceXKeys[fragment] = vm.PublicKeyMultibase
		}
	}

	serviceTypeMap := map[string]string{
		"SolidPod":             "pod",
		"GreyThingProfile":     "profile",
		"GreyThingEventStream": "events",
	}
	for _, svc := range doc.Service {
		if key, ok := serviceTypeMap[svc.Type]; ok {
			services[key] = svc.ServiceEndpoint
		}
	}

	recoveryPolicy = doc.RecoveryPolicy

	return
}
