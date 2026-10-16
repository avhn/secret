package roles

import (
	"strings"
	"testing"
)

func TestAudit21PrinterNormalization(t *testing.T) {
	for _, tc := range []struct {
		source string
		deny   bool
		always bool
	}{
		{"op --account synthetic read op://vault/item/password", true, false},
		{"op --cache read op://v/i/p", true, false},
		{"op --cache item get synthetic --reveal", true, false},
		{"op --cache item list", false, false},
		{"op -- read op://v/i/p", true, false},
		{"gh -- auth token", true, false},
		{"kubectl -- create token synthetic", true, false},
		{"op -- item list", false, false},
		{"gh -- repo view synthetic", false, false},
		{"kubectl -- get pods", false, false},
		{"xsel -- synthetic", false, false},
		{"op -- item get synthetic --reveal", true, false},
		{"op --account=synthetic --session session read op://vault/item/password", true, false},
		{"op --vault synthetic item --account synthetic get item --reveal", true, false},
		{"op item --vault=synthetic get item --fields=password", true, false},
		{"op --account read item list", false, false},
		{"op --vault get item list", false, false},
		{"security -q find-generic-password -wa synthetic", true, false},
		{"security -v find-internet-password -ws synthetic", true, false},
		{"security find-generic-password -ga synthetic", true, true},
		{"security find-generic-password -ag -w", true, false},
		{"security find-generic-password -a -w", false, false},
		{"security find-generic-password -a synthetic", false, false},
		{"docker --context synthetic inspect container", true, false},
		{"docker --host unix:///synthetic/socket inspect container", true, false},
		{"docker --context=synthetic container inspect container --format=json", true, false},
		{"docker compose --project-directory synthetic config", true, true},
		{"docker --context inspect ps", false, false},
		{"docker inspect container --format={{.Name}} -f{{.Config.Env}}", true, false},
		{"docker inspect container -f{{.Config.Env}} --format={{.Name}}", true, false},
		{"kubectl get secret synthetic --output=name -oyaml", true, true},
		{"kubectl get secret synthetic -oyaml --output=name", true, true},
		{"docker --host synthetic inspect container --format={{.Name}}", false, false},
		{"docker compose --project-directory config ps", false, false},
		{"gh config --host synthetic.invalid get oauth_token", true, true},
		{"gh --host=synthetic.invalid config get oauth_token", true, true},
		{"gh config --host oauth_token get editor", false, false},
		{"xsel -ob", true, false}, {"xsel -bo", true, false},
		{"xsel --output", true, false}, {"xsel -bi", false, false},
		{"kwallet-query -rsynthetic wallet", true, false},
		{"kwallet-query --read-password=synthetic wallet", true, false},
		{"kwallet-query -f read wallet", false, false},
		{"npm --global config list --long", true, false},
		{"npm config --global list -l", true, false},
		{"npm --global config get registry", false, false},
		{"npm --registry list config get registry", false, false},
		{"pnpm --dir synthetic config list", true, true},
		{"yarn --cwd synthetic config list", true, true},
		{"php -i", true, true}, {"php --info", true, true},
		{"secret-tool --unknown synthetic lookup service public", true, false},
		{"secret-tool lookup --unknown synthetic service public", true, false},
		{"secret-tool --unknown synthetic search service public", true, true},
		{"secret-tool clear service lookup", false, false},
		{"secret-tool --label public store service search", false, false},
		{"keyring --unknown synthetic get service user", true, false},
		{"keyring -b synthetic set get user", false, false},
		{"make -fpublic.mk", false, false},
		{"make -sCpublic -fREADME.md", false, false},
		{"make -sfpcredential-file", false, false},
		{"make -sp -fpublic.mk", true, false},
		{"make --print-data-base", true, false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			words := strings.Fields(tc.source)
			for _, direct := range []bool{false, true} {
				got := PrinterReason(words[0], words[1:], direct)
				if (got != "") != (tc.deny && (!direct || tc.always)) {
					t.Errorf("direct=%v: reason=%q, printer=%v always=%v", direct, got, tc.deny, tc.always)
				}
			}
		})
	}
}
