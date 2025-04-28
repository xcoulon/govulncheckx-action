package govulncheck

import (
	"log"
	"time"

	"github.com/xcoulon/govulncheckx-action/internal/configuration"
)

type OpenVexReport struct {
	Statements []Statement `json:"statements,omitempty"`
}

const Affected = "affected"
const NotAffected = "not_affected"

type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Products        []Product     `json:"products,omitempty"`
	Status          string        `json:"status"`
	Justfication    string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
}

type Vulnerability struct {
	ID          string   `json:"@id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases,omitempty"`
}

type Product struct {
	ID            string         `json:"@id"`
	Subcomponents []Subcomponent `json:"subcomponents,omitempty"`
}

type Subcomponent struct {
	ID string `json:"@id"`
}

func (r *OpenVexReport) PruneIgnoreVulns(logger *log.Logger, ignored []configuration.Vulnerability) {
	statements := make([]Statement, 0, len(r.Statements))
statements:
	for _, s := range r.Statements {
		if s.Status == Affected {
			// remove if ignored
			for _, vuln := range ignored {
				if s.Vulnerability.Name == vuln.ID {
					if vuln.Expires.Before(time.Now()) {
						// if expired, do not ignore it anymore
						logger.Printf("vulnerability '%s' not ignored: expired, please reevaluated", vuln.ID)
						statements = append(statements, s)
					}
					continue statements
				}
			}
			statements = append(statements, s)
		}
	}
	r.Statements = statements
}
