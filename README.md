# SBOM
A simple Python script that creates a software bill of materials (SBOM) from all git repositories inside a given directory.

## Running
```
python sbom.py <directory>
```

## Known issues and bugs
Passing an entire drive as the argument requires a trailing slash. For example, on Windows, `python sbom.py D:` will not work correctly, and `python sbom.py D:\` should be used instead. This will also process the Recycle Bin on that drive, and the program will fail if it finds files to process there.

## Future ideas
* feature to check whether a package (given by name and version range) is in the SBOM
* deduplicate SBOM entries, merging version ranges
* more extensive support of the `requirements.txt` file format