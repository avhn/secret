package roles

import (
	"strings"
	"testing"
)

func TestAudit19InterspersedPrinterOptions(t *testing.T) {
	for _, tc := range []struct {
		command string
		printer bool
	}{
		{"aws ecr --region us-east-1 get-login-password", true},
		{"aws --profile synthetic ecr --region=us-east-1 --no-cli-pager get-login-password", true},
		{"aws sts --output json get-session-token", true},
		{"aws sso --region us-east-1 get-role-credentials", true},
		{"aws configure --profile synthetic export-credentials", true},
		{"aws configure --region us-east-1 get aws_session_token", true},
		{"gcloud auth --project synthetic print-access-token", true},
		{"gcloud auth --project=synthetic application-default --quiet print-access-token", true},
		{"gcloud config --account synthetic config-helper", true},
		{"kubectl create --namespace default token synthetic", true},
		{"kubectl --context synthetic create --namespace=default token synthetic", true},
		{"az account --subscription synthetic get-access-token", true},
		{"az acr --subscription=synthetic login --expose-token", true},
		{"doctl auth --context synthetic token", true},
		{"doctl --verbose auth token", true},
		{"doctl --verbose=true auth token", true},
		{"doctl auth -v token", true},
		{"doctl --verbose auth list", false},
		{"aws ecr get-login-password --region", true},
		{"aws ecr --region get-login-password describe-repositories", false},
		{"aws configure --profile export-credentials get region", false},
		{"gcloud auth --project print-access-token list", false},
		{"gcloud auth --project synthetic list", false},
		{"kubectl create --namespace token deployment synthetic", false},
		{"kubectl create --namespace default deployment synthetic", false},
		{"az acr --subscription login list", false},
		{"doctl auth --context token list", false},
		{"aws -- --region synthetic ecr get-login-password", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			words := strings.Fields(tc.command)
			for _, direct := range []bool{false, true} {
				want := ""
				if tc.printer && !direct {
					want = Printer
				}
				if got := PrinterReason(words[0], words[1:], direct); got != want {
					t.Errorf("direct=%v: got %q, want %q", direct, got, want)
				}
			}
		})
	}
}
