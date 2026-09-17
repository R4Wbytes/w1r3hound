package main

import "encoding/json"

// Workflow is an MCP prompt enriched with visual metadata for the GUI.
type Workflow struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Icon        string         `json:"icon"`
	Defaults    map[string]any `json:"defaults"`
}

type workflowInfo struct {
	Title    string
	Desc     string
	Icon     string
	Defaults map[string]any
}

var workflowMeta = map[string]workflowInfo{
	"bug_bounty_recon": {
		Title:    "Bug Bounty Recon",
		Desc:     "Comprehensive reconnaissance workflow optimized for bug bounty programs",
		Icon:     "target",
		Defaults: map[string]any{"source": "mcp", "passive": false},
	},
	"passive_recon": {
		Title:    "Passive Recon",
		Desc:     "OSINT-only reconnaissance with no active traffic to the target",
		Icon:     "eye",
		Defaults: map[string]any{"source": "mcp", "passive": true},
	},
	"subdomain_takeover_check": {
		Title:    "Subdomain Takeover",
		Desc:     "Discover subdomains and check for takeover vulnerabilities",
		Icon:     "link",
		Defaults: map[string]any{"source": "mcp", "passive": false},
	},
	"full_recon": {
		Title:    "Full Recon",
		Desc:     "All modules, active scanning, standard port range",
		Icon:     "radar",
		Defaults: map[string]any{"source": "mcp", "passive": false},
	},
	"web_assessment": {
		Title:    "Web Assessment",
		Desc:     "Web-focused assessment: crawling, JS analysis, directory brute-force, API scanning",
		Icon:     "shield",
		Defaults: map[string]any{"source": "mcp", "passive": false},
	},
	"exhaustive_recon": {
		Title: "Exhaustive Stealth",
		Desc:  "Maximum-depth stealth recon — all 21 modules, full ports, throttled for low detection",
		Icon:  "microscope",
		Defaults: map[string]any{
			"source": "mcp", "passive": false,
			"ports": "full", "concurrency": 5, "rate": 3,
			"timeout_sec": 30, "wayback_limit": 10000,
			"crawl_pages": 500, "js_files": 200,
			"dir_ext": ".bak,.php,.asp,.aspx,.jsp,.zip,.tar.gz,.sql,.conf,.env,.xml,.json,.yml,.log,.old,.txt,.swp,~",
		},
	},
}

func enrichWorkflows(raw json.RawMessage) []Workflow {
	var prompts []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &prompts); err != nil {
		return nil
	}
	out := make([]Workflow, 0, len(prompts))
	for _, p := range prompts {
		meta, ok := workflowMeta[p.Name]
		if !ok {
			continue
		}
		out = append(out, Workflow{
			Name:        p.Name,
			Title:       meta.Title,
			Description: meta.Desc,
			Icon:        meta.Icon,
			Defaults:    meta.Defaults,
		})
	}
	return out
}
