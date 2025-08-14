package probe

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProbeStore(t *testing.T) {
	store := GetDefaultStore()
	assert.True(t, len(store.GetAllProbes()) > 0)

}
