"""Least-privilege tool scopes enforced by the harness (not by prompt obedience): a role maps to the capabilities its ToolBox is built with, and a call outside the
scope is refused before it reaches the tool. Unknown roles get the read-only scope (fail closed)."""
SCOPES = {
    "researcher": {"write": False, "web": True, "tools": {"read_file", "list_files", "grep", "find_files", "fetch_url", "ask_user"}},
    "reviewer":   {"write": False, "web": False, "tools": {"read_file", "list_files", "grep", "find_files", "ask_user"}},
    "coder":      {"write": True,  "web": False, "tools": {"read_file", "list_files", "grep", "find_files", "write_file", "edit_file", "ask_user"}},
    "readonly":   {"write": False, "web": False, "tools": {"read_file", "list_files", "grep", "find_files"}},
}
MUTATING = {"write_file", "edit_file", "run_command", "terminal"}


def scope_for(role):
    return SCOPES.get(str(role or "").lower(), SCOPES["readonly"])


def allowed(role, tool):
    s = scope_for(role); return tool in s["tools"] and (s["write"] or tool not in MUTATING)


def guard(role, box_call):
    """Wrap a ToolBox.call-like function: out-of-scope tools return an ERROR string (counted by the loop's failure/spin detectors) and are never executed."""
    def call(name, args):
        if not allowed(role, name): return f"ERROR: tool '{name}' is outside the '{role}' scope ({', '.join(sorted(scope_for(role)['tools']))})"
        return box_call(name, args)
    return call
