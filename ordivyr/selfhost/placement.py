"""Endpoint binding and tenant helpers for Board steps."""

def binding(endpoint, price=None):
    return {'endpoint': {k: endpoint.get(k) for k in
                         ('id', 'provider', 'base', 'protocol', 'paid', 'authorized', 'caps', 'capabilities', 'models')},
            'price': list(price) if price is not None else None}


def task_tenant(step, default='default'):
    return (step.get('resource') or {}).get('tenant', default)
