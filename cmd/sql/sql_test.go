package sql

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDriverNew(t *testing.T) {
	assert.True(t, isEmailValid("sergey.fdsaf@gmail.com"))
	assert.True(t, isEmailValid("sergey.fdasf+234234@gmail.com"))


	assert.False(t, isEmailValid("sergey.fdsaf+234234@com"))
	assert.False(t, isEmailValid("sergey.fdsaf@234234@gmail.com"))
	assert.False(t, isEmailValid("sergey.fdasf@gmail"))

	assert.False(t, isEmailValid("1'\\\""))
	assert.False(t, isEmailValid("\\\\"))
	assert.False(t, isEmailValid("@@LyTrF"))
	assert.False(t, isEmailValid("JyI="))
	assert.False(t, isEmailValid("8PKbPLbq"))
	assert.False(t, isEmailValid("<rodrigo.apas99@gmail.com>me@rodri.pw"))
	assert.False(t, isEmailValid("<rodrigo.apas99@gmail.com>ssbsawtligjhc2u2na@wearehackerone.com"))
	assert.False(t, isEmailValid("aiacobelli.sec@gmail.com,alejandro.iacobelli@mercadolibre.com"))
	assert.False(t, isEmailValid("aiacobelli.sec@gmail.com,alejandro.iacobelli@mercadolibre.com"))
}
