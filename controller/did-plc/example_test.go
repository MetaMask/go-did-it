package did_plc_test

import (
	"context"
	"fmt"
	"log"

	did_plc "github.com/MetaMask/go-did-it/controller/did-plc"
	"github.com/MetaMask/go-did-it/crypto"
	"github.com/MetaMask/go-did-it/crypto/secp256k1"
)

// Example demonstrates the full did:plc workflow: create, update, and audit a DID.
//
// In production use did_plc.NewRegistry() (no options) to target https://plc.directory.
// The example calls a live registry; run it with a real key and network access.
func Example() {
	ctx := context.Background()

	// Generate a secp256k1 rotation key. P-256 is also accepted by default.
	pub, priv, err := secp256k1.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	reg := did_plc.NewRegistry()

	// Create a new DID. RotationKeys control who may sign future updates.
	ctrl, err := reg.Create(ctx, priv, did_plc.Op{
		RotationKeys: []crypto.PublicKey{pub},
		VerificationMethods: map[string]crypto.PublicKey{
			"atproto": pub,
		},
		AlsoKnownAs: []string{"at://alice.example.com"},
		Services: map[string]did_plc.Service{
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

	// Update uses a read-modify-write callback: the current document state is
	// passed in, the caller mutates it, and the result is signed and submitted.
	err = ctrl.Update(ctx, priv, func(op did_plc.Op) (did_plc.Op, error) {
		op.AlsoKnownAs = append(op.AlsoKnownAs, "at://alice.new.example.com")
		return op, nil
	})
	if err != nil {
		log.Fatal(err)
	}

	// Obtain a Controller for an existing DID (e.g. loaded from a database).
	ctrl2 := reg.Controller(ctrl.DidStr())
	fmt.Println("same DID:", ctrl2.DidStr() == ctrl.DidStr())

	// Audit fetches the full operation history and validates CID integrity,
	// low-S signatures, and prev-pointer continuity.
	entries, err := ctrl.Audit(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		if e.Op == nil {
			fmt.Println("tombstone at", e.CID)
		} else {
			fmt.Println("op at", e.CID, "handles:", e.Op.AlsoKnownAs)
		}
	}
}
