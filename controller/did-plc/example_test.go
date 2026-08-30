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
	ctrl, err := reg.Create(ctx, priv, didplcctl.State{
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
	// The signer must hold one of that state's rotation keys.
	err = ctrl.Update(ctx, priv, func(state didplcctl.State) (didplcctl.State, error) {
		state.AlsoKnownAs = append(state.AlsoKnownAs, "at://alice.new.example.com")
		return state, nil
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
		fmt.Println("head:", head.CID, head.State.AlsoKnownAs)
	}

	// Audit reports the whole history, forks included, after validating it.
	entries, err := ctrl.Audit(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		switch {
		case e.State == nil:
			fmt.Println("tombstone at", e.CID)
		case e.Nullified:
			fmt.Println("nullified op at", e.CID)
		default:
			fmt.Println("op at", e.CID, "handles:", e.State.AlsoKnownAs)
		}
	}
}

// ExampleWithFullChainVerification shows the two ways a controller can learn the state it
// is about to build on.
func ExampleWithFullChainVerification() {
	// By default, reading the state costs one small request (GET /:did/log/last) whatever
	// the length of the history, and the registry's answer is taken on trust.
	fast := didplcctl.NewRegistry()

	// With full verification, the DID's whole history is fetched (GET /:did/log/audit) and
	// replayed from the genesis operation, so the registry is not trusted to report the
	// state honestly — including its account of which operations a recovery nullified.
	// It costs a response proportional to the length of the history, per operation signed.
	verifying := didplcctl.NewRegistry(didplcctl.WithFullChainVerification())

	_, _ = fast, verifying
}
