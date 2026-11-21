"""Board error types (HTTP status + stable code). Own module so accounts/billing mixins and service can all import them."""
class BoardError(Exception):
    status = 400; code = "error"
    def __init__(self, msg="", **ctx): super().__init__(msg); self.ctx = ctx
class NotFound(BoardError): status = 404; code = "not_found"
class Forbidden(BoardError): status = 403; code = "forbidden"
class Invalid(BoardError): status = 422; code = "invalid"
class Conflict(BoardError): status = 409; code = "conflict"
class QuotaError(BoardError): status = 429; code = "quota_exceeded"
class Unavailable(BoardError): status = 503; code = "unavailable"
