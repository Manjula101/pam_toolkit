# OPA Policy: Deny root access unless JIT-approved
# Zero-Trust Privileged Access Control

package pam.root_access

default allow = false

allow {
    input.user != "root"
}

allow {
    input.user == "root"
    input.approval.status == "approved"
    input.approval.expires > time.now_ns()
}

deny[msg] {
    not allow
    msg := "Root access denied — requires JIT approval"
}

# Demo tests
test_allow_non_root_approved {
    allow with input as {
        "user": "root",
        "approval": {"status": "approved", "expires": time.now_ns() + 7200000000000}
    }
}
