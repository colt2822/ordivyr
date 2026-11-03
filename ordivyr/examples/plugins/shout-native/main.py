def register(api):
    api.add_tool("shout", {"description": "Upper-case the given text", "readOnly": True,
                           "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
                           "fn": lambda args: str(args.get("text", "")).upper()})
