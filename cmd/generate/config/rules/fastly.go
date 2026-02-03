package rules

import (
	"github.com/betterleaks/betterleaks/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/cmd/generate/secrets"
	"github.com/betterleaks/betterleaks/config"
)

func FastlyAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
		RuleID:      "fastly-api-token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"fastly"}, utils.AlphaNumericExtended("32"), true),

		Keywords: []string{"fastly"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("fastly", secrets.NewSecret(utils.AlphaNumericExtended("32")))
	return utils.Validate(r, tps, nil)
}
