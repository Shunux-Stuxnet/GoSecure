import importlib.util

if importlib.util.find_spec("_cloudflare") is not None:
    import _workers_sdk_entropy_import_context  # noqa: F401

if importlib.util.find_spec("_cloudflare") is not None:
    import _workers_sdk_entropy_import_context  # noqa: F401
