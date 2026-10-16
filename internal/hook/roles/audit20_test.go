package roles

import (
	"strings"
	"testing"
)

func TestAudit20PrinterOptions(t *testing.T) {
	for _, source := range []string{
		"aws --cli-binary-format raw-in-base64-out ecr get-login-password",
		"aws --cli-auto-prompt off ecr get-login-password",
		"aws ecr --unknown z get-login-password",
		"aws sts --cli-binary-format raw-in-base64-out get-session-token",
		"aws --color on ecr get-login-password",
		"aws --no-sign-request ecr get-login-password",
		"aws --color off ecr get-login-password",
		"aws --no-cli-auto-prompt ecr get-login-password",
		"gcloud --billing-project synthetic auth print-access-token",
		"doctl -c synthetic auth token",
		"kubectl --request-timeout=30s create token synthetic",
		"gcloud --unknownflag=1 auth print-access-token",
		"vault --unknown x print token",
		"heroku --unknown auth:token",
		"glab --unknown auth status --show-token",
		"az account --subscription s get-access-token",
		"doctl --trace auth token",
	} {
		t.Run(source, func(t *testing.T) {
			words := strings.Fields(source)
			if got := PrinterReason(words[0], words[1:], false); got != Printer {
				t.Fatalf("got %q, want %q", got, Printer)
			}
		})
	}
	// Unknown options can occur before, between or after action words, and
	// can be boolean, value-taking or attached. Their arity cannot hide a
	// printer, while validated direct consumers keep the same exception.
	for _, source := range []string{
		"aws ecr get-login-password", "aws sts get-session-token",
		"aws ecr-public get-login-password", "aws ecr get-authorization-token",
		"aws sts assume-role", "aws sts assume-role-with-web-identity",
		"aws sts assume-role-with-saml", "aws sts get-federation-token",
		"aws sso get-role-credentials", "aws configure export-credentials",
		"aws configure get aws_secret_access_key",
		"gcloud config config-helper", "gcloud auth print-access-token",
		"gcloud auth application-default print-access-token",
		"gcloud auth print-identity-token", "az account get-access-token",
		"az acr login --expose-token", "heroku auth:token", "vault print token",
		"vault token lookup", "doctl auth token", "glab auth status --show-token",
		"gh auth token", "kubectl create token synthetic", "kubectl config view --raw",
		"direnv export json",
	} {
		words := strings.Fields(source)
		for i := 1; i <= len(words); i++ {
			for _, option := range [][]string{{"--unknown"}, {"--unknown", "synthetic"}, {"--unknown=synthetic"}, {"-Z", "synthetic"}} {
				args := append([]string{}, words[1:i]...)
				args = append(args, option...)
				args = append(args, words[i:]...)
				for _, direct := range []bool{false, true} {
					want := ""
					if !direct {
						want = Printer
					}
					if got := PrinterReason(words[0], args, direct); got != want {
						t.Errorf("%s %q direct=%v: got %q, want %q", words[0], args, direct, got, want)
					}
				}
			}
		}
	}
	for _, source := range []string{
		"aws s3 ls", "aws --profile p s3 ls", "gcloud auth list",
		"az account show", "kubectl get pods", "doctl --trace auth list",
		"vault --unknown x token capabilities", "glab --unknown auth status",
		"aws get-login-password ecr", "gcloud print-access-token auth",
	} {
		words := strings.Fields(source)
		if got := PrinterReason(words[0], words[1:], false); got != "" {
			t.Errorf("safe command %q: %s", source, got)
		}
	}
}
