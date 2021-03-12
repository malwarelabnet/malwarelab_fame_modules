import os

from fame.core.module import ProcessingModule, ModuleInitializationError
from fame.common.utils import tempdir

try:
    import patoolib
    HAVE_PATOOL = True
except ImportError:
    HAVE_PATOOL = False

class ExtractPatool(ProcessingModule):
    name = "extract_patool"
    description = "Extract most compressed archives using patool."
    acts_on = ["zip", "rar", "7z", "iso"]

    config = [
        {
            "name": "maximum_extracted_files",
            "type": "integer",
            "default": 5,
            "description": "If there are more files than this value in the archive, extracted files will not be processed.",
        },
        {
            "name": "maximum_automatic_analyses",
            "type": "integer",
            "default": 1,
            "description": "If there are more files than this value in the archive, no analyses will be automatically created for extracted files.",
        },
    ]

    def initialize(self):
        if not HAVE_PATOOL:
            raise ModuleInitializationError(self, "Missing dependency: patoolib")

    def each(self, target):
        self.results = {"warnings": []}
        namelist = []
        tmpdir = tempdir()
        try:
            patoolib.extract_archive(target, outdir=tmpdir)
            should_extract = len(os.listdir(tmpdir)) <= self.maximum_extracted_files
            should_analyze = len(os.listdir(tmpdir)) <= self.maximum_automatic_analyses
            if should_extract:
                for filepath in os.listdir(tmpdir):
                    namelist.append(filepath)
                    fullpath = tmpdir + "/" + filepath
                    self.add_extracted_file(fullpath, automatic_analysis=should_analyze)
        except Exception as error:
            self.log("debug", "{}".format(error))
            self.results["warnings"].append("Could not extract.")

        self.results["files"] = namelist
        return True