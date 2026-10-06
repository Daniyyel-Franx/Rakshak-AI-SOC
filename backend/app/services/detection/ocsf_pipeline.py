"""pySigma ProcessingPipeline for OCSF mappings."""
from __future__ import annotations

from sigma.pipelines.base import ProcessingPipeline
from sigma.processing.pipeline import ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation

def get_ocsf_pipeline() -> ProcessingPipeline:
    """pySigma ProcessingPipeline for OCSF mappings.

    MAPPINGS:
      Image          -> process.file.path
      ParentImage    -> actor.process.file.path
      CommandLine    -> process.cmd_line
      User           -> user.name
      TargetFilename -> file.path
      TargetImage    -> process.file.path
    """
    return ProcessingPipeline(
        name="OCSF Mapping Pipeline",
        items=[
            ProcessingItem(
                transformation=FieldMappingTransformation({
                    "Image": "process.file.path",
                    "ParentImage": "actor.process.file.path",
                    "CommandLine": "process.cmd_line",
                    "User": "user.name",
                    "TargetFilename": "file.path",
                    "TargetImage": "process.file.path",
                })
            )
        ]
    )
