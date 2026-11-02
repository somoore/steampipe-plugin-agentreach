package agentreach

// The SQL surface must stay list-only: the collector reads local
// configuration, so a query must never be able to name a filesystem path. No
// table may declare a key column, and none may gain a Get function.

import (
	"context"
	"testing"
)

func TestTablesStayListOnly(t *testing.T) {
	for name, tbl := range Plugin(context.Background()).TableMap {
		if tbl.List == nil {
			t.Errorf("%s: List is nil", name)
		}
		if tbl.Get != nil {
			t.Errorf("%s: has a Get function", name)
		}
		if tbl.List != nil && len(tbl.List.KeyColumns) > 0 {
			t.Errorf("%s: key columns %v let a query choose the input", name, tbl.List.KeyColumns)
		}
	}
}
