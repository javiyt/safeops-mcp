package telegram

import "testing"

func TestParseOpenClawResponseExtractsApprovalMetadata(t *testing.T) {
	resp := parseOpenClawResponse("Restart requires approval_id=apr_1 and confirmation_code=4821 before it expires.")
	if resp.ApprovalID != "apr_1" {
		t.Fatalf("ApprovalID = %q", resp.ApprovalID)
	}
	if resp.Code != "4821" {
		t.Fatalf("Code = %q", resp.Code)
	}
}
