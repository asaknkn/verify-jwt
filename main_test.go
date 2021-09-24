package main

import "testing"

func TestHandler(t *testing.T) {

	tests := []struct {
		name string
		want string
	}{
		{
			name: "Success",
			want: "Hello, Paypay",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := handler(events.APIGatewayProxyRequest{})

			if got.Body != tt.want {
				t.Errorf("got = %v, want = %v", got.Body, tt.want)
			}
		})
	}

}
