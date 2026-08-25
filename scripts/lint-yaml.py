import glob
import os
import sys

try:
    import yaml
except ImportError:
    print("PyYAML is not installed; skipping YAML lint")
    sys.exit(0)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PATTERNS = [
    "deploy/**/*.yaml", "deploy/**/*.yml",
    "examples/**/*.yaml", "examples/**/*.yml",
    "tests/**/*.yaml", "tests/**/*.yml",
    ".github/**/*.yml", ".github/**/*.yaml",
    "*.yaml", "*.yml",
]
SKIP_TEMPLATED = (os.path.join("deploy", "helm", "rokh-oghab", "templates"),)

class StrictLoader(yaml.SafeLoader):
    pass


def no_duplicate_keys(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None,
                "duplicate key %r; the later value silently overrides the "
                "earlier one" % (key,),
                key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, no_duplicate_keys)


def discover():
    for pattern in PATTERNS:
        for path in sorted(glob.glob(os.path.join(ROOT, pattern), recursive=True)):
            rel = os.path.relpath(path, ROOT)
            if any(rel.startswith(skip) for skip in SKIP_TEMPLATED):
                continue
            yield path


targets = [os.path.abspath(a) for a in sys.argv[1:]] or list(discover())

failures = 0
checked = 0
for path in targets:
    rel = os.path.relpath(path, ROOT)
    try:
        with open(path) as fh:
            list(yaml.load_all(fh, Loader=StrictLoader))
        checked += 1
    except Exception as exc:
        print("INVALID YAML: %s\n  %s" % (rel, exc))
        failures += 1

print("checked %d YAML files, %d invalid" % (checked, failures))
sys.exit(1 if failures else 0)
