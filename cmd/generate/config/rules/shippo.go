package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func ShippoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "shippo-api-token",
		Description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
		Regex:       utils.GenerateUniqueTokenRegex(`shippo_(?:live|test)_[a-fA-F0-9]{40}`, false),
		Entropy:     2,
		Keywords: []string{
			"shippo_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("shippo", "shippo_live_"+secrets.NewSecret(utils.Hex("40")))
	tps = append(tps, utils.GenerateSampleSecrets("shippo", "shippo_test_"+secrets.NewSecret(utils.Hex("40")))...)
	return utils.Validate(r, tps, nil)
}
