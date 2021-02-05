import sys
from pathlib import Path
from subprocess import run

"""Run the python file specified by the first command line argument

This also adds all the directories in between the root and the current file
to the python path"""


run_path = sys.argv[1]
# root of repo
directory_root = Path(__file__).parent.resolve()
# path to run
run_file = Path(run_path).resolve()
components = run_file.relative_to(directory_root).parents
# TODO: find out how to avoid adding the root of the repo twice
# list of paths to add to PYTHONPATH
paths = []
for p in components:
    path_to_append = str(directory_root / p)
    paths.append(path_to_append)

# call python in a subprocess instead of using exec because this
# gives better error messages
pythonpath = ":".join(paths)
run(["python", "-u", run_file], env={"PYTHONPATH": pythonpath})


# with open(run_path) as f:
#     exec(f.read())
