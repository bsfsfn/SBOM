import csv
import json
import os
import sys

import subprocess

def find_git_repo_paths(directory_path):
   """Returns a list of all git repository paths inside a directory at the given path."""
   git_repo_paths = []

   for root, dirs, files in os.walk(directory_path):
      if '.git' in dirs:
         repo_path = os.path.abspath(root)
         git_repo_paths.append(repo_path)

   return git_repo_paths

def parse_pip(path):
   """Parses a `requirements.txt` file at the given path.

   Assumes that the `requirements.txt` file has no empty lines (except possibly one final empty line), and that each line is exactly of the form `name==version`.
   
   Returns a dictionary with package name keys and package version values."""
   deps = {}

   with open(path) as file:
      for line in file:
         line = line.rstrip()
         item = line.split('==')
         deps[item[0]] = item[1]

   return deps

# list of keys that can contain dependencies in npm package.json and package-lock.json files
DEPS_KEYS = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

# package.json specification docs: https://docs.npmjs.com/cli/configuring-npm/package-json
def parse_npm(path):
   """Parses a `package.json` file at the given path.
   
   Assumes all the dependencies are contained within `DEPS_KEYS`.

   Versions are reported unmodified (in addition to single version numbers, they can also be ranges, URLs or paths).
   
   Returns a list of pairs (package name, package version)."""
   deps = []

   with open(path) as file:
      data = json.load(file)

      for dep_key in DEPS_KEYS:
         deps_chunk = data.get(dep_key)

         if deps_chunk is not None:
            for dep_name, dep_ver in deps_chunk.items():
               deps.append((dep_name, dep_ver))

   return deps

# package-lock.json specification docs: https://docs.npmjs.com/cli/configuring-npm/package-lock-json
def parse_npmlock(path):
   """Parses a `package-lock.json` file at the given path.

   Assumes all the dependencies are contained within `DEPS_KEYS`.

   Assumes that the `package-lock.json`'s `lockfileVersion` is at least `2` (`parse_npmlock` only parses the `packages` key, and not the legacy `dependencies` key).
   
   Package names are reported unmodified (in addition to just the package name, they can also be full local paths).

   Versions are reported unmodified (in addition to single version numbers, they can also be ranges, URLs or paths).

   Returns a list of pairs (package name, package version)."""
   deps = []

   with open(path) as file:
      data = json.load(file)

      packages_data = data.get('packages')

      for pkg_name, pkg_data in packages_data.items():
         if pkg_name == '':
            # this data was already parsed in `parse_npm`
            continue

         pkg_ver = pkg_data.get('version')
         deps.append((pkg_name, pkg_ver))

         for dep_key in DEPS_KEYS:
            deps_chunk = pkg_data.get(dep_key)

            if deps_chunk is not None:
               for dep_name, dep_ver in deps_chunk.items():
                  deps.append((dep_name, dep_ver))

   return deps

def get_commit_hash(repo_path):
   """Returns the latest commit's hash of the git repository at the given path."""
   command = ['git', 'log', '--format=\"%H\"', '-n', '1']
   proc = subprocess.run(command, cwd = repo_path, capture_output = True)
   sha = proc.stdout.strip()[1:-1].decode()

   return sha

def create_sbom_entry(name, version, type, path, commit_hash):
   """Creates a SBOM entry with the given values.
   
   The SBOM is a list of SBOM entry dictionaries. Creating SBOM entries using exclusively this method ensures a consistent structure.
   
   Returns the created SBOM entry dictionary."""
   dep_d = {}

   dep_d['name'] = name
   dep_d['version'] = version
   dep_d['type'] = type
   dep_d['path'] = path
   dep_d['commit_hash'] = commit_hash

   return dep_d

if len(sys.argv) != 2:
   print('Error: incorrect number of arguments.')
   print(f'Usage: {sys.argv[0]} <directory>')
   sys.exit(1)

directory_path = sys.argv[1]
git_repo_paths = find_git_repo_paths(directory_path)

print(f'Found {len(git_repo_paths)} git repositories in \'{directory_path}\'')

sbom = []

# find all dependencies
for repo_path in git_repo_paths:
   commit_hash = get_commit_hash(repo_path)

   pip_path = os.path.join(repo_path, 'requirements.txt')
   npm_path = os.path.join(repo_path, 'package.json')

   if os.path.exists(pip_path):
      pip_deps = parse_pip(pip_path)

      for dep in pip_deps:
         sbom_entry = create_sbom_entry(dep, pip_deps[dep], 'pip', pip_path, commit_hash)

         sbom.append(sbom_entry)

   if os.path.exists(npm_path):
      npm_deps = parse_npm(npm_path)

      for dep in npm_deps:
         sbom_entry = create_sbom_entry(dep[0], dep[1], 'npm', npm_path, commit_hash)

         sbom.append(sbom_entry)

      npmlock_path = os.path.join(repo_path, 'package-lock.json')

      if os.path.exists(npmlock_path):
         npmlock_deps = parse_npmlock(npmlock_path)

         for dep in npmlock_deps:
            sbom_entry = create_sbom_entry(dep[0], dep[1], 'npm', npmlock_path, commit_hash)

            sbom.append(sbom_entry)

# sort the SBOM by name then version
sbom = sorted(sbom, key = lambda x: (x['name'], x['version']))

# save the SBOM to .csv and .json files
csv_path = os.path.join(directory_path, 'sbom.csv')
json_path = os.path.join(directory_path, 'sbom.json')

with open(csv_path, 'w', newline = '') as file:
   wr = csv.DictWriter(file, sbom[0].keys())
   wr.writeheader()
   wr.writerows(sbom)

   print('Saved SBOM in CSV format to', csv_path)

with open(json_path, 'w') as file:
   json.dump(sbom, file, indent = 3)

   print('Saved SBOM in CSV format to', json_path)
