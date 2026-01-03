//! Command-line control utility for composefs repositories and images.
//!
//! `cfsctl` provides a comprehensive interface for managing composefs repositories,
//! creating and mounting filesystem images, handling OCI containers, and performing
//! repository maintenance operations like garbage collection.

use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use clap::{Parser, Subcommand};

use rustix::fs::CWD;

use composefs_boot::{write_boot, BootOps};

use composefs::{
    fsverity::{FsVerityHashValue, Sha256HashValue, Sha512HashValue},
    repository::Repository,
};

/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    /// Operate on repo at path
    #[clap(long, group = "repopath")]
    repo: Option<PathBuf>,
    /// Operate on repo at standard user location $HOME/.var/lib/composefs
    #[clap(long, group = "repopath")]
    user: bool,
    /// Operate repo at standard system location /sysroot/composefs
    #[clap(long, group = "repopath")]
    system: bool,

    /// Use sha256 instead of sha512 as object ID for legacy composefs repos
    #[clap(long)]
    use_sha256_object_id: bool,

    /// Sets the repository to insecure before running any operation and
    /// prepend '?' to the composefs kernel command line when writing
    /// boot entry.
    #[clap(long)]
    insecure: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[cfg(feature = "oci")]
#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Stores a tar layer file as a splitstream in the repository.
    ImportLayer {
        sha256: String,
        name: Option<String>,
    },
    /// Lists the contents of a tar stream
    LsLayer {
        /// the name of the stream to list, either an sha256 stream ID or prefixed with 'ref/'
        name: String,
    },
    /// Dump full content of the rootfs of a stored OCI image to a composefs dumpfile and write to stdout
    Dump {
        /// the name of the stream that points to the OCI image manifest, either an sha256 stream ID or prefixed with 'ref/'
        config_name: String,
        /// verity sha512 digest for the manifest stream to be verified against
        config_verity: Option<String>,
    },
    /// Pull an OCI image to be stored in repo then prints the stream and verity digest of its manifest
    Pull {
        /// source image reference, as accepted by skopeo
        image: String,
        /// optional reference name for the manifest, use as 'ref/<name>' elsewhere
        name: Option<String>,
    },
    /// Compute the composefs image object id of the rootfs of a stored OCI image
    ComputeId {
        /// the name of the stream that points to the OCI image manifest, either an sha256 stream ID or prefixed with 'ref/'
        config_name: String,
        /// verity sha512 digest for the manifest stream to be verified against
        config_verity: Option<String>,
        /// wether bootable preparation should be performed on the image before computation
        #[clap(long)]
        bootable: bool,
    },
    /// Create the composefs image of the rootfs of a stored OCI image, commit it to the repo, and print its image object ID
    CreateImage {
        /// the name of the stream that points to the OCI image manifest, either an sha256 stream ID or prefixed with 'ref/'
        config_name: String,
        /// verity sha512 digest for the manifest stream to be verified against
        config_verity: Option<String>,
        /// wether bootable preparation should be performed on the image before committing
        #[clap(long)]
        bootable: bool,
        /// optional reference name for the image, use as 'ref/<name>' elsewhere
        #[clap(long)]
        image_name: Option<String>,
    },
    /// Seal a stored OCI image by creating a cloned manifest with embedded verity digest (a.k.a. composefs image object ID)
    /// in the repo, then prints the stream and verity digest of the new sealed manifest
    Seal {
        /// the name of the stream that points to the OCI image manifest, either an sha256 stream ID or prefixed with 'ref/'
        config_name: String,
        /// verity sha512 digest for the manifest stream to be verified against
        config_verity: Option<String>,
    },
    /// Mounts a stored and sealed OCI image by looking up its composefs image. Note that the composefs image must be built
    /// and committed to the repo first
    Mount {
        /// the name of the stream that points to the OCI image manifest, either an sha256 stream ID or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
    /// Create the composefs image of the rootfs of a stored OCI image, perform bootable preparation, commit it to the repo,
    /// then configure boot for the image by writing new boot resources and bootloader entires to boot partition. Performs
    /// state preparation for composefs-setup-root consumption as well. Note that state preparation here is not suitable for
    /// consumption by bootc.
    PrepareBoot {
        /// the name of the stream that points to the OCI image manifest, either an sha256 stream ID or prefixed with 'ref/'
        config_name: String,
        /// verity sha512 digest for the manifest stream to be verified against
        config_verity: Option<String>,
        /// boot partition mount point
        #[clap(long, default_value = "/boot")]
        bootdir: PathBuf,
        /// boot entry identifier to use. by default use id provided by the image or kernel version
        #[clap(long)]
        entry_id: Option<String>,
        /// additional kernel command line
        #[clap(long)]
        cmdline: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        /// the name of the stream to cat, either an sha256 stream ID or prefixed with 'ref/'
        name: String,
    },
    /// Perform garbage collection
    GC {
        // digest of root images for gc operations
        #[clap(long, short = 'i')]
        root_images: Vec<String>,
        // digest of root streams for gc operations
        #[clap(long, short = 's')]
        root_streams: Vec<String>,
        // collects orphan objects only
        #[clap(long)]
        orphans_only: bool,
        // actually perform deletion instead of just printing removals
        #[clap(short, long)]
        force: bool,
    },
    /// Imports a composefs image (unsafe!)
    ImportImage { reference: String },
    /// Commands for dealing with OCI images and layers
    #[cfg(feature = "oci")]
    Oci {
        #[clap(subcommand)]
        cmd: OciCommand,
    },
    /// Mounts a composefs image, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either an object ID digest or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
    /// Read rootfs located at a path, add all files to the repo, then create the composefs image of the rootfs,
    /// commit it to the repo, and print its image object ID
    CreateImage {
        /// the path to read rootfs from
        path: PathBuf,
        /// wether bootable preparation should be performed on the image before committing
        #[clap(long)]
        bootable: bool,
        /// also store rootfs directory's own metadata in the image
        #[clap(long)]
        stat_root: bool,
        /// optional reference name for the image, use as 'ref/<name>' elsewhere
        image_name: Option<String>,
    },
    /// Read rootfs located at a path, add all files to the repo, then compute the composefs image object id of the rootfs.
    /// Note that this does not create or commit the compose image itself.
    ComputeId {
        /// the path to read rootfs from
        path: PathBuf,
        /// wether bootable preparation should be performed on the image before computation
        #[clap(long)]
        bootable: bool,
        /// also include rootfs directory's own metadata for the computation
        #[clap(long)]
        stat_root: bool,
    },
    /// Read rootfs located at a path, add all files to the repo, then dump full content of the rootfs to a composefs dumpfile
    /// and write to stdout.
    CreateDumpfile {
        /// the path to read rootfs from
        path: PathBuf,
        /// wether bootable preparation should be performed on the image before the dump
        #[clap(long)]
        bootable: bool,
        /// also include rootfs directory's own metadata in the dump
        #[clap(long)]
        stat_root: bool,
    },
    /// Open a composefs image and print all object files it refers to
    ImageObjects {
        /// the name of the image to read, either an object ID digest or prefixed with 'ref/'
        name: String,
    },
    #[cfg(feature = "http")]
    Fetch { url: String, name: String },
}

fn verity_opt<ObjectID>(opt: &Option<String>) -> Result<Option<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    Ok(match opt {
        Some(value) => Some(FsVerityHashValue::from_hex(value)?),
        None => None,
    })
}

fn open_repo<ObjectID>(args: &App) -> Result<Repository<ObjectID>>
where
    ObjectID: FsVerityHashValue,
{
    let mut repo = (if let Some(path) = &args.repo {
        Repository::open_path(CWD, path)
    } else if args.system {
        Repository::open_system()
    } else if args.user {
        Repository::open_user()
    } else if rustix::process::getuid().is_root() {
        Repository::open_system()
    } else {
        Repository::open_user()
    })?;

    repo.set_insecure(args.insecure);

    Ok(repo)
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = App::parse();

    if args.use_sha256_object_id {
        run_cmd_with_repo(open_repo::<Sha256HashValue>(&args)?, args).await
    } else {
        run_cmd_with_repo(open_repo::<Sha512HashValue>(&args)?, args).await
    }
}

async fn run_cmd_with_repo<ObjectID>(repo: Repository<ObjectID>, args: App) -> Result<()>
where
    ObjectID: FsVerityHashValue,
{
    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        }
        Command::Cat { name } => {
            repo.merge_splitstream(&name, None, &mut std::io::stdout())?;
        }
        Command::ImportImage { reference } => {
            let image_id = repo.import_image(&reference, &mut std::io::stdin())?;
            println!("{}", image_id.to_id());
        }
        #[cfg(feature = "oci")]
        Command::Oci { cmd: oci_cmd } => match oci_cmd {
            OciCommand::ImportLayer { name, sha256 } => {
                let object_id = composefs_oci::import_layer(
                    &Arc::new(repo),
                    &composefs::util::parse_sha256(sha256)?,
                    name.as_deref(),
                    &mut std::io::stdin(),
                )?;
                println!("{}", object_id.to_id());
            }
            OciCommand::LsLayer { name } => {
                composefs_oci::ls_layer(&repo, &name)?;
            }
            OciCommand::Dump {
                ref config_name,
                ref config_verity,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                fs.print_dumpfile()?;
            }
            OciCommand::ComputeId {
                ref config_name,
                ref config_verity,
                bootable,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                let id = fs.compute_image_id();
                println!("{}", id.to_hex());
            }
            OciCommand::CreateImage {
                ref config_name,
                ref config_verity,
                bootable,
                ref image_name,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(&repo)?;
                }
                let image_id = fs.commit_image(&repo, image_name.as_deref())?;
                println!("{}", image_id.to_id());
            }
            OciCommand::Pull { ref image, name } => {
                let (sha256, verity) =
                    composefs_oci::pull(&Arc::new(repo), image, name.as_deref(), None).await?;

                println!("sha256 {}", hex::encode(sha256));
                println!("verity {}", verity.to_hex());
            }
            OciCommand::Seal {
                ref config_name,
                ref config_verity,
            } => {
                let verity = verity_opt(config_verity)?;
                let (sha256, verity) =
                    composefs_oci::seal(&Arc::new(repo), config_name, verity.as_ref())?;
                println!("sha256 {}", hex::encode(sha256));
                println!("verity {}", verity.to_id());
            }
            OciCommand::Mount {
                ref name,
                ref mountpoint,
            } => {
                composefs_oci::mount(&repo, name, mountpoint, None)?;
            }
            OciCommand::PrepareBoot {
                ref config_name,
                ref config_verity,
                ref bootdir,
                ref entry_id,
                ref cmdline,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(&repo, config_name, verity.as_ref())?;
                let entries = fs.transform_for_boot(&repo)?;
                let id = fs.commit_image(&repo, None)?;

                let Some(entry) = entries.into_iter().next() else {
                    anyhow::bail!("No boot entries!");
                };

                let cmdline_refs: Vec<&str> = cmdline.iter().map(String::as_str).collect();
                write_boot::write_boot_simple(
                    &repo,
                    entry,
                    &id,
                    args.insecure,
                    bootdir,
                    None,
                    entry_id.as_deref(),
                    &cmdline_refs,
                )?;

                let state = args
                    .repo
                    .as_ref()
                    .map(|p: &PathBuf| p.parent().unwrap())
                    .unwrap_or(Path::new("/sysroot"))
                    .join("state/deploy")
                    .join(id.to_hex());

                create_dir_all(state.join("var"))?;
                create_dir_all(state.join("etc/upper"))?;
                create_dir_all(state.join("etc/work"))?;
            }
        },
        Command::ComputeId {
            ref path,
            bootable,
            stat_root,
        } => {
            let mut fs = composefs::fs::read_filesystem(CWD, path, Some(&repo), stat_root)?;
            if bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.compute_image_id();
            println!("{}", id.to_hex());
        }
        Command::CreateImage {
            ref path,
            bootable,
            stat_root,
            ref image_name,
        } => {
            let mut fs = composefs::fs::read_filesystem(CWD, path, Some(&repo), stat_root)?;
            if bootable {
                fs.transform_for_boot(&repo)?;
            }
            let id = fs.commit_image(&repo, image_name.as_deref())?;
            println!("{}", id.to_id());
        }
        Command::CreateDumpfile {
            ref path,
            bootable,
            stat_root,
        } => {
            let mut fs = composefs::fs::read_filesystem(CWD, path, Some(&repo), stat_root)?;
            if bootable {
                fs.transform_for_boot(&repo)?;
            }
            fs.print_dumpfile()?;
        }
        Command::Mount { name, mountpoint } => {
            repo.mount_at(&name, &mountpoint)?;
        }
        Command::ImageObjects { name } => {
            let objects = repo.objects_for_image(&name)?;
            for object in objects {
                println!("{}", object.to_id());
            }
        }
        Command::GC {
            root_images,
            root_streams,
            orphans_only,
            force,
        } => {
            repo.gc(root_images, root_streams, orphans_only, force)?;
        }
        #[cfg(feature = "http")]
        Command::Fetch { url, name } => {
            let (sha256, verity) = composefs_http::download(&url, &name, Arc::new(repo)).await?;
            println!("sha256 {}", hex::encode(sha256));
            println!("verity {}", verity.to_hex());
        }
    }
    Ok(())
}
