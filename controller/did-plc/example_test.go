package didplcctl_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	didplcctl "github.com/MetaMask/go-did-it/controller/did-plc"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
)

// Example demonstrates the did:plc controller workflow: create, update and audit a DID.
//
// It targets the live registry at https://plc.directory, so it is compiled but not run
// as a test. Running it registers a real, permanent DID.
func Example() {
	ctx := context.Background()

	// Generate a secp256k1 rotation key. P-256 is also allowed by the specification.
	pub, priv, err := secp256k1.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	reg := didplcctl.NewRegistry()

	// Create a new DID. RotationKeys control who may sign future operations, so the
	// signer has to be one of them: a genesis operation is self-signed.
	ctrl, err := reg.Create(ctx, priv, didplcctl.Op{
		RotationKeys: []crypto.PublicKey{pub},
		VerificationMethods: map[string]crypto.PublicKey{
			"atproto": pub,
		},
		AlsoKnownAs: []string{"at://alice.example.com"},
		Services: map[string]didplcctl.Service{
			"atproto_pds": {
				Type:     "AtprotoPersonalDataServer",
				Endpoint: "https://pds.example.com",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("created:", ctrl.DidStr())

	// Update reads the current state, hands it to the callback, and submits the result.
	// By default the state is verified from the genesis operation before being signed.
	err = ctrl.Update(ctx, priv, func(op didplcctl.Op) (didplcctl.Op, error) {
		op.AlsoKnownAs = append(op.AlsoKnownAs, "at://alice.new.example.com")
		return op, nil
	})
	if err != nil {
		log.Fatal(err)
	}

	// Obtain a Controller for an existing DID, e.g. one loaded from a database.
	ctrl2, err := reg.Controller(ctrl.DidStr())
	if err != nil {
		log.Fatal(err)
	}
	head, err := ctrl2.Head(ctx)
	if errors.Is(err, didplcctl.ErrDeactivated) {
		fmt.Println("this DID has been tombstoned")
	} else if err != nil {
		log.Fatal(err)
	} else {
		fmt.Println("head:", head.CID, head.Op.AlsoKnownAs)
	}

	// Audit reports the whole history, forks included, after validating it.
	entries, err := ctrl.Audit(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		switch {
		case e.Op == nil:
			fmt.Println("tombstone at", e.CID)
		case e.Nullified:
			fmt.Println("nullified op at", e.CID)
		default:
			fmt.Println("op at", e.CID, "handles:", e.Op.AlsoKnownAs)
		}
	}
}

// ExampleWithChainVerification shows the cheaper alternative for a process that operates
// on the same DID often, and already trusts its registry.
func ExampleWithChainVerification() {
	// VerifyFullChain, the default, reads GET /:did/log and verifies it from the genesis
	// operation, so the registry is not trusted to report the state honestly. It costs a
	// response proportional to the length of the history.
	verifying := didplcctl.NewRegistry()

	// VerifyHeadOnly reads GET /:did/log/last instead: one small response whatever the
	// history, at the cost of taking the registry's answer on trust.
	fast := didplcctl.NewRegistry(
		didplcctl.WithChainVerification(didplcctl.VerifyHeadOnly),
	)

	_, _ = verifying, fast
}
