import runpy
import pathlib


def test_run_data_pipeline_script():
    script = pathlib.Path(__file__).with_name('test_data_pipeline_script.py')
    # Execute the script; exceptions will fail the test
    runpy.run_path(str(script), run_name='__main__')
