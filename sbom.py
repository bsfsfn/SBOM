import csv
import json
import os
import sys

import subprocess

def find_git_repo_paths(directory_path):
   git_repo_paths = []

   for root, dirs, files in os.walk(directory_path):
      if '.git' in dirs:
         repo_path = os.path.abspath(root)
         git_repo_paths.append(repo_path)

   return git_repo_paths

# assumes the `requirements.txt` file has no empty lines (except one final one), and each line is exactly `name==version`
def parse_pip(path):
   """"""
   deps = {}

   with open(path) as file:
      for line in file:
         line = line.rstrip()
         item = line.split('==')
         deps[item[0]] = item[1]

   return deps

# assumes keys point to a version, not URL or path
# version ranges are reported unmodified
def parse_npm(path):
   deps = {}

   with open(path) as file:
      data = json.load(file)

      # package.json specification docs: https://docs.npmjs.com/cli/configuring-npm/package-json
      # assumes all the dependencies are contained within these keys:
      deps_keys = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']

      for dep_key in deps_keys:
         deps_chunk = data.get(dep_key)
         if deps_chunk is not None:
            deps |= deps_chunk

   return deps

def parse_npmlock(path):
   deps = {}

   # TODO

   return deps

def get_commit_hash(repo_path):
   command = ['git', 'log', '--format=\"%H\"', '-n', '1']
   proc = subprocess.run(command, cwd = repo_path, capture_output = True)
   sha = proc.stdout.strip()[1:-1].decode()

   return sha

if len(sys.argv) != 2:
   print('Error: incorrect number of arguments.')
   print(f'Usage: {sys.argv[0]} <directory>')
   sys.exit(1)

directory_path = sys.argv[1]
git_repo_paths = find_git_repo_paths(directory_path)

print(f'Found {len(git_repo_paths)} git repositories in \'{directory_path}\'')

sbom_data = []

for repo_path in git_repo_paths:
   commit_hash = get_commit_hash(repo_path)

   pip_path = os.path.join(repo_path, 'requirements.txt')
   npm_path = os.path.join(repo_path, 'package.json')

   if os.path.exists(pip_path):
      pip_deps = parse_pip(pip_path)

      for dep in pip_deps:
         dep_d = {}

         dep_d['name'] = dep
         dep_d['version'] = pip_deps[dep]
         dep_d['type'] = 'pip'
         dep_d['path'] = pip_path
         dep_d['commit_hash'] = commit_hash

         sbom_data.append(dep_d)

   if os.path.exists(npm_path):
      npm_deps = parse_npm(npm_path)

      for dep in npm_deps:
         dep_d = {}

         dep_d['name'] = dep
         dep_d['version'] = npm_deps[dep]
         dep_d['type'] = 'npm'
         dep_d['path'] = npm_path
         dep_d['commit_hash'] = commit_hash

         sbom_data.append(dep_d)

      npmlock_path = os.path.join(repo_path, 'package-lock.json')
      npmlock_deps = parse_npmlock(npmlock_path)
      # TODO

# sort SBOM by name then version
sbom_data = sorted(sbom_data, key = lambda x: (x['name'], x['version']))

csv_path = os.path.join(directory_path, 'sbom.csv')
json_path = os.path.join(directory_path, 'sbom.json')

with open(csv_path, 'w', newline = '') as file:
   wr = csv.DictWriter(file, sbom_data[0].keys())
   wr.writeheader()
   wr.writerows(sbom_data)

   print('Saved SBOM in CSV format to', csv_path)

with open(json_path, 'w') as file:
   json.dump(sbom_data, file, indent = 3)

   print('Saved SBOM in CSV format to', json_path)
