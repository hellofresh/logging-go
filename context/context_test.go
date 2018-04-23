package context

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scenario string
		function func(*testing.T)
	}{
		{
			scenario: "when set the context",
			function: testSetContext,
		},
		{
			scenario: "when the context is nil",
			function: testGetLoggerWhenContextIsNil,
		},
		{
			scenario: "when the logger is not the context",
			function: testGetLoggerWhenNoLogIsOnContext,
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			test.function(t)
		})
	}
}

func testSetContext(t *testing.T) {
	ctx := context.Background()
	ctx = New(ctx)

	logger := WithContext(ctx)
	require.NotNil(t, logger)
}

func testGetLoggerWhenContextIsNil(t *testing.T) {
	client := WithContext(nil)
	require.NotNil(t, client)
}

func testGetLoggerWhenNoLogIsOnContext(t *testing.T) {
	client := WithContext(context.Background())
	require.NotNil(t, client)
}
