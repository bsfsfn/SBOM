# SBOM
A simple Python script that creates a software bill of materials (SBOM) from all git repositories inside a given directory.

## Running
```
python sbom.py <directory>
```

## Known issues and bugs
Passing an entire drive as the argument requires a trailing slash. For example, on Windows, `python sbom.py D:` will not work correctly, and `python sbom.py D:\` should be used instead.

## Future ideas
* feature to check whether a package (given by name and version range) is in the SBOM
* deduplicate SBOM entries, merging version ranges