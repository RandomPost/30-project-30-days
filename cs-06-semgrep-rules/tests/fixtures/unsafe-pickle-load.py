import pickle
import cPickle
import dill
import shelve


def vulnerable(blob, fh):
    # ruleid: unsafe-pickle-load
    pickle.loads(blob)
    # ruleid: unsafe-pickle-load
    pickle.load(fh)
    # ruleid: unsafe-pickle-load
    cPickle.loads(blob)
    # ruleid: unsafe-pickle-load
    dill.loads(blob)
    # ruleid: unsafe-pickle-load
    pickle.Unpickler(fh).load()
    # ruleid: unsafe-pickle-load
    shelve.open("cache")


def safe(blob, fh, obj):
    # ok: unsafe-pickle-load
    pickle.dumps(obj)
    # ok: unsafe-pickle-load
    pickle.dump(obj, fh)
    # ok: unsafe-pickle-load
    json.loads(blob)
    # ok: unsafe-pickle-load
    other.loads(blob)
