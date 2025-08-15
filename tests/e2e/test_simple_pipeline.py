# Moved from simple_pipeline_test.py for pytest discovery

import runpy
import pathlib


def test_run_simple_pipeline_script():
    script = pathlib.Path(__file__).resolve().parents[1] / 'scripts' / 'simple_pipeline_standalone.py'
    runpy.run_path(str(script), run_name='__main__')
