import os

import emulator


s3_path = 's3://chebotarev-core-dump/coredump'

emu = emulator.Emulator(
    s3_path,
    mapping_load_kwargs={
        'filename_map': lambda x: f'{os.path.dirname(s3_path)}/{os.path.basename(x)}'
    }
)

with emu.reserve(0x17) as a: # Place for std::string
    emu.call(
        '_ZNK2DB16PipelineExecutor12dumpPipelineEv', # DB::PipelineExecutor::dumpPipeline() const
        a.start, # returns std::string
        0x00007f352d3c9818 # this
    )

    print(a.read_str())
