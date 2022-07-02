import os

import emucore


s3_path = 's3://chebotarev-core-dump'

emu = emucore.EmuCore(
    f'{s3_path}/coredump',
    #load_symbols=f'{s3_path}/058d7f7cde734632fbfd572bfa1f6325cdd929.debug', FIXME does not work
    mapping_load_kwargs={
        'filename_map': lambda x: f'{s3_path}/{os.path.basename(x)}'
    }
)

with emu.reserve(0x17) as a: # Place for std::string
    emu.call(
        0x000000000f907090, # DB::PipelineExecutor::dumpPipeline() const == _ZNK2DB16PipelineExecutor12dumpPipelineEv
        a.start, # returns std::string
        0x00007f352d3c9818 # this
    )

    print(a.read_str())
