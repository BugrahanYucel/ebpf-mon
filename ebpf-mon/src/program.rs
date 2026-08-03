use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProgramError {
    #[error("loading probe")]
    LoadingProbe(#[from] aya::BpfError),
    #[error("program not found {0}")]
    ProgramNotFound(String),
    #[error("incorrect program type {0}")]
    ProgramTypeError(String),
    #[error("failed program load {program}")]
    ProgramLoadError {
        program: String,
        #[source]
        program_error: Box<aya::programs::ProgramError>,
    },
    #[error("failed program attach {program}")]
    ProgramAttachError {
        program: String,
        #[source]
        program_error: Box<aya::programs::ProgramError>,
    },
    #[error(transparent)]
    MapError(#[from] aya::maps::MapError),
    #[error("map not found {0}")]
    MapNotFound(String),
    #[error("map already used {0}")]
    MapAlreadyUsed(String),
    // #[error("perf buffer error {0}")]
    // PerfBuffer(#[from] PerfBufferError),
    // #[error("loading BTF {0}")]
    // BtfError(#[from] BtfError),
    // #[error("running background aya task {0}")]
    // JoinError(#[from] JoinError),
    // #[error("could not find the inode of {path}")]
    // InodeError {
    //     path: PathBuf,
    //     io_error: Box<std::io::Error>,
    // },
}