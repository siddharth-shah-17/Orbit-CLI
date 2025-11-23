package models

// SVECTOR provider and model definitions
const (
	ProviderSVECTOR ModelProvider = "svector"
)

const (
	SVECTORSpec35Pro      ModelID = "spec-3-5-pro"
	SVECTORSpec3Turbo     ModelID = "spec-3-turbo"
	SVECTORdotcode1fast   ModelID = ".dotcode-1-fast"
	SVECTORdotcode1       ModelID = ".dotcode-1"
	SVECTORSpec35Fast     ModelID = "spec-3-5-fast"
	SVECTORSpec35Thinking ModelID = "spec-3-5-thinking"
	SVECTORSpec2Mini      ModelID = "spec-2-mini"
)

var SVECTORModels = map[ModelID]Model{
	SVECTORSpec35Pro: {
		ID:                 SVECTORSpec35Pro,
		Name:               "Spec-3.5 Pro",
		Provider:           ProviderSVECTOR,
		APIModel:           "spec-3-5-pro",
		CostPer1MIn:        3.10,
		CostPer1MInCached:  2.00,
		CostPer1MOutCached: 5.00,
		CostPer1MOut:       8.20,
		ContextWindow:      64000,
		DefaultMaxTokens:   2048,
		CanReason:          true,
	},
	SVECTORdotcode1fast: {
		ID:                 SVECTORdotcode1fast,
		Name:               ".dotcode-1-fast",
		Provider:           ProviderSVECTOR,
		APIModel:           ".dotcode-1-fast",
		CostPer1MIn:        3.60,
		CostPer1MInCached:  1.6,
		CostPer1MOutCached: 3.20,
		CostPer1MOut:       8.80,
		ContextWindow:      64000,
		DefaultMaxTokens:   2048,
		CanReason:          true,
	},
	SVECTORdotcode1: {
		ID:                 SVECTORdotcode1,
		Name:               ".dotcode-1",
		Provider:           ProviderSVECTOR,
		APIModel:           ".dotcode-1",
		CostPer1MIn:        5.10,
		CostPer1MInCached:  2.00,
		CostPer1MOutCached: 2.90,
		CostPer1MOut:       9.20,
		ContextWindow:      64000,
		DefaultMaxTokens:   2048,
		CanReason:          true,
	},
	SVECTORSpec3Turbo: {
		ID:               SVECTORSpec3Turbo,
		Name:             "Spec-3-Turbo",
		Provider:         ProviderSVECTOR,
		APIModel:         "spec-3-turbo",
		CostPer1MIn:      1.20,
		CostPer1MOut:     2.10,
		ContextWindow:    63000,
		DefaultMaxTokens: 2048,
		CanReason:        true,
	},
	SVECTORSpec35Fast: {
		ID:               ModelID("spec-3-5-fast"),
		Name:             "Spec-3.5-Fast",
		Provider:         ProviderSVECTOR,
		APIModel:         "spec-3-5-fast",
		CostPer1MIn:      4.10,
		CostPer1MOut:     6.20,
		ContextWindow:    64000,
		DefaultMaxTokens: 2048,
		CanReason:        false,
	},
	SVECTORSpec35Thinking: {
		ID:               ModelID("spec-3-5-thinking"),
		Name:             "Spec-3.5-Thinking",
		Provider:         ProviderSVECTOR,
		APIModel:         "spec-3-5-thinking",
		CostPer1MIn:      3.50,
		CostPer1MOut:     8.20,
		ContextWindow:    64000,
		DefaultMaxTokens: 2048,
		CanReason:        true,
	},
	SVECTORSpec2Mini: {
		ID:               ModelID("spec-2-mini"),
		Name:             "Spec-2-Mini",
		Provider:         ProviderSVECTOR,
		APIModel:         "spec-2-mini",
		CostPer1MIn:      0.50,
		CostPer1MOut:     1.00,
		ContextWindow:    32000,
		DefaultMaxTokens: 1024,
		CanReason:        false,
	},
}
