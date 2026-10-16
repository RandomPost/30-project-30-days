import yaml
from yaml import SafeLoader, CSafeLoader


def vulnerable(data, stream):
    # ruleid: unsafe-yaml-load
    yaml.load(data)
    # ruleid: unsafe-yaml-load
    yaml.load(stream, Loader=yaml.Loader)
    # ruleid: unsafe-yaml-load
    yaml.load(stream, Loader=yaml.UnsafeLoader)
    # ruleid: unsafe-yaml-load
    yaml.load(stream, yaml.FullLoader)
    # ruleid: unsafe-yaml-load
    yaml.unsafe_load(stream)
    # ruleid: unsafe-yaml-load
    yaml.load_all(stream)


def safe(data, stream):
    # ok: unsafe-yaml-load
    yaml.safe_load(data)
    # ok: unsafe-yaml-load
    yaml.load(stream, Loader=yaml.SafeLoader)
    # ok: unsafe-yaml-load
    yaml.load(stream, Loader=SafeLoader)
    # ok: unsafe-yaml-load
    yaml.load(stream, yaml.CSafeLoader)
    # ok: unsafe-yaml-load
    yaml.safe_load_all(stream)
    # ok: unsafe-yaml-load
    json.load(stream)
