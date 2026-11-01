package magiclinktest_test

import (
	"sync/atomic"
	"testing"

	"github.com/FacileStudio/porte"
	"github.com/FacileStudio/porte/magiclink/magiclinktest"
)

func TestMemoryConforms(t *testing.T) {
	var next atomic.Int64
	magiclinktest.Conformance(t,
		func(*testing.T) porte.MagicLinkStore { return magiclinktest.NewMemory() },
		func(*testing.T) int64 { return next.Add(1) },
	)
}
