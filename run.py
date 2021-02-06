import sys
from pathlib import Path
from subprocess import run

"""Run the python file specified by the first command line argument

This also adds the current directory to the python path and runs it as
a package"""

run_path = sys.argv[1]
# root of repo
directory_root = Path(__file__).parent.resolve()
# path to run
run_file = Path(run_path).resolve()
relative_path = run_file.relative_to(directory_root)
suffix_removed = relative_path.with_suffix("")
# this is a relative path, so parts doesn't include a leading slash
parts = suffix_removed.parts

module_name = ".".join(parts)
# set the current directory so that importing from another set without a relative import
run(["python", "-m", module_name], cwd=directory_root)
