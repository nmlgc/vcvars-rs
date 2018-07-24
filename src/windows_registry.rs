// Copyright 2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A helper module to probe the Windows Registry when looking for
//! windows-specific tools.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::mem;
use std::path::{Path, PathBuf};

use com;
use registry::{RegistryKey, LOCAL_MACHINE};
use setup_config::{SetupConfiguration, SetupInstance};
use Tool;

#[cfg(windows)]
macro_rules! otry {
    ($expr:expr) => {
        match $expr {
            Some(val) => val,
            None => return None,
        }
    };
}

/// Similar to the `find` function above, this function will attempt the same
/// operation (finding a MSVC tool in a local install) but instead returns a
/// `Tool` which may be introspected.
#[cfg(not(windows))]
pub fn find_tool(_target: &str, _tool: &str) -> Option<Tool> {
    None
}

/// Documented above.
#[cfg(windows)]
pub fn find_tool(target: &str, tool: &str) -> Option<Tool> {
    // This logic is all tailored for MSVC, if we're not that then bail out
    // early.
    if !target.contains("msvc") {
        return None;
    }

    // Looks like msbuild isn't located in the same location as other tools like
    // cl.exe and lib.exe. To handle this we probe for it manually with
    // dedicated registry keys.
    if tool.contains("msbuild") {
        return find_msbuild(target);
    }

    if tool.contains("devenv") {
        return find_devenv(target);
    }

    None
}

/// Finds the latest installed Visual C++ version with a linker for the
/// given target.
pub fn find_msvc_latest(target: &str) -> Option<VCInstance> {
    find_msvc_15(target)
        .or_else(|| find_msvc_14(target))
        .or_else(|| find_msvc_12(target))
        .or_else(|| find_msvc_11(target))
}

/// A version of Visual Studio
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum VsVers {
    /// Visual Studio 11 (2012)
    Vs11,
    /// Visual Studio 12 (2013)
    Vs12,
    /// Visual Studio 14 (2015)
    Vs14,
    /// Visual Studio 15 (2017)
    Vs15,

    /// Hidden variant that should not be matched on. Callers that want to
    /// handle an enumeration of `VsVers` instances should always have a default
    /// case meaning that it's a VS version they don't understand.
    #[doc(hidden)]
    #[allow(bad_style)]
    __Nonexhaustive_do_not_match_this_or_your_code_will_break,
}

impl fmt::Display for VsVers {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                VsVers::Vs11 => "Visual Studio 11 (2012)",
                VsVers::Vs12 => "Visual Studio 12 (2013)",
                VsVers::Vs14 => "Visual Studio 14 (2015)",
                VsVers::Vs15 => "Visual Studio 15 (2017)",
                _ => "(unknown)",
            }
        )
    }
}

/// Find the most recent installed version of Visual Studio
///
/// This is used by the cmake crate to figure out the correct
/// generator.
#[cfg(not(windows))]
pub fn find_vs_version() -> Result<VsVers, String> {
    Err(format!("not windows"))
}

/// Documented above
#[cfg(windows)]
pub fn find_vs_version() -> Result<VsVers, String> {
    use std::env;

    match env::var("VisualStudioVersion") {
        Ok(version) => match &version[..] {
            "15.0" => Ok(VsVers::Vs15),
            "14.0" => Ok(VsVers::Vs14),
            "12.0" => Ok(VsVers::Vs12),
            vers => Err(format!(
                "\n\n\
                 unsupported or unknown VisualStudio version: {}\n\
                 if another version is installed consider running \
                 the appropriate vcvars script before building this \
                 crate\n\
                 ",
                vers
            )),
        },
        _ => {
            // Check for the presense of a specific registry key
            // that indicates visual studio is installed.
            if has_msbuild_version("15.0") {
                Ok(VsVers::Vs15)
            } else if has_msbuild_version("14.0") {
                Ok(VsVers::Vs14)
            } else if has_msbuild_version("12.0") {
                Ok(VsVers::Vs12)
            } else {
                Err(format!(
                    "\n\n\
                     couldn't determine visual studio generator\n\
                     if VisualStudio is installed, however, consider \
                     running the appropriate vcvars script before building \
                     this crate\n\
                     "
                ))
            }
        }
    }
}

/// An installation of a specific Visual C++ version.
pub struct VCInstance {
    version: VsVers,
    vcinstalldir: PathBuf,
    libs: Vec<PathBuf>,
    path: Vec<PathBuf>,
    include: Vec<PathBuf>,
}

impl VCInstance {
    fn new(version: VsVers, vcinstalldir: PathBuf) -> VCInstance {
        VCInstance {
            version,
            vcinstalldir,
            libs: Vec::new(),
            path: Vec::new(),
            include: Vec::new(),
        }
    }

    /// Returns which version of Visual C++ this is an instance of.
    pub fn version(&self) -> &VsVers {
        &self.version
    }

    /// Returns all environment variables necessary for this MSVC instance to be
    /// usable, as a vector of (name, value) tuples.
    pub fn env(self) -> Vec<(OsString, OsString)> {
        let join = |var: Vec<PathBuf>| env::join_paths(var.into_iter()).unwrap();
        vec![
            ("LIB".into(), join(self.libs)),
            ("PATH".into(), join(self.path)),
            ("INCLUDE".into(), join(self.include)),
            (
                "VCINSTALLDIR".into(),
                self.vcinstalldir.as_os_str().to_os_string(),
            ),
        ]
    }
}

/// Returns the environment of the Visual Studio 2017 installation, or None if
/// it is not installed.
pub fn find_msvc_15(target: &str) -> Option<VCInstance> {
    // In MSVC 15 (2017) MS once again changed the scheme for locating
    // the tooling.  Now we must go through some COM interfaces, which
    // is super fun for Rust.
    //
    // Note that much of this logic can be found [online] wrt paths, COM, etc.
    //
    // [online]: https://blogs.msdn.microsoft.com/vcblog/2017/03/06/finding-the-visual-c-compiler-tools-in-visual-studio-2017/
    otry!(com::initialize().ok());

    let config = otry!(SetupConfiguration::new().ok());
    let iter = otry!(config.enum_all_instances().ok());
    for instance in iter {
        let instance = otry!(instance.ok());
        let vc = vs15_instance(target, &instance);
        if vc.is_some() {
            return vc;
        }
    }

    None
}

fn vs15_instance(target: &str, instance: &SetupInstance) -> Option<VCInstance> {
    let (instance_path, bin_path, host_dylib_path, lib_path, include_path) =
        otry!(vs15_vc_paths(target, instance));
    let tool_path = bin_path.join("link.exe");
    if !tool_path.exists() {
        return None;
    };

    let mut tool = VCInstance::new(VsVers::Vs15, instance_path.join("VC"));
    tool.path.push(host_dylib_path);
    tool.libs.push(lib_path);
    tool.include.push(include_path);

    if let Some((atl_lib_path, atl_include_path)) = atl_paths(target, &bin_path) {
        tool.libs.push(atl_lib_path);
        tool.include.push(atl_include_path);
    }

    otry!(add_sdks(&mut tool, target));

    Some(tool)
}

fn vs15_vc_paths(
    target: &str,
    instance: &SetupInstance,
) -> Option<(PathBuf, PathBuf, PathBuf, PathBuf, PathBuf)> {
    let instance_path: PathBuf = otry!(instance.installation_path().ok()).into();
    let version_path =
        instance_path.join(r"VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt");
    let mut version_file = otry!(File::open(version_path).ok());
    let mut version = String::new();
    otry!(version_file.read_to_string(&mut version).ok());
    let version = version.trim();
    let host = match host_arch() {
        X86 => "X86",
        X86_64 => "X64",
        _ => return None,
    };
    let target = otry!(lib_subdir(target));
    // The directory layout here is MSVC/bin/Host$host/$target/
    let path = instance_path.join(r"VC\Tools\MSVC").join(version);
    // This is the path to the toolchain for a particular target, running
    // on a given host
    let bin_path = path
        .join("bin")
        .join(&format!("Host{}", host))
        .join(&target);
    // But! we also need PATH to contain the target directory for the host
    // architecture, because it contains dlls like mspdb140.dll compiled for
    // the host architecture.
    let host_dylib_path = path
        .join("bin")
        .join(&format!("Host{}", host))
        .join(&host.to_lowercase());
    let lib_path = path.join("lib").join(&target);
    let include_path = path.join("include");
    Some((
        instance_path,
        bin_path,
        host_dylib_path,
        lib_path,
        include_path,
    ))
}

fn atl_paths(target: &str, path: &Path) -> Option<(PathBuf, PathBuf)> {
    let atl_path = path.join("atlfmc");
    let sub = otry!(lib_subdir(target));
    if atl_path.exists() {
        Some((atl_path.join("lib").join(sub), atl_path.join("include")))
    } else {
        None
    }
}

/// Returns the environment of the Visual Studio 2015 installation, or None if
/// it is not installed.
pub fn find_msvc_14(target: &str) -> Option<VCInstance> {
    // For MSVC 14 we need to find the Universal CRT as well as either
    // the Windows 10 SDK or Windows 8.1 SDK.
    let vcdir = otry!(get_vc_dir("14.0"));
    let mut tool = otry!(get_instance(VsVers::Vs14, &vcdir, target));
    otry!(add_sdks(&mut tool, target));
    Some(tool)
}

fn add_sdks(tool: &mut VCInstance, target: &str) -> Option<()> {
    let sub = otry!(lib_subdir(target));
    let (ucrt, ucrt_version) = otry!(get_ucrt_dir());

    tool.path
        .push(ucrt.join("bin").join(&ucrt_version).join(sub));

    let ucrt_include = ucrt.join("include").join(&ucrt_version);
    tool.include.push(ucrt_include.join("ucrt"));

    let ucrt_lib = ucrt.join("lib").join(&ucrt_version);
    tool.libs.push(ucrt_lib.join("ucrt").join(sub));

    if let Some((sdk, version)) = get_sdk10_dir() {
        tool.path.push(sdk.join("bin").join(sub));
        let sdk_lib = sdk.join("lib").join(&version);
        tool.libs.push(sdk_lib.join("um").join(sub));
        let sdk_include = sdk.join("include").join(&version);
        tool.include.push(sdk_include.join("um"));
        tool.include.push(sdk_include.join("cppwinrt"));
        tool.include.push(sdk_include.join("winrt"));
        tool.include.push(sdk_include.join("shared"));
    } else if let Some(sdk) = get_sdk81_dir() {
        tool.path.push(sdk.join("bin").join(sub));
        let sdk_lib = sdk.join("lib").join("winv6.3");
        tool.libs.push(sdk_lib.join("um").join(sub));
        let sdk_include = sdk.join("include");
        tool.include.push(sdk_include.join("um"));
        tool.include.push(sdk_include.join("winrt"));
        tool.include.push(sdk_include.join("shared"));
    }

    Some(())
}

/// Returns the environment of the Visual Studio 2013 installation, or None if
/// it is not installed.
pub fn find_msvc_12(target: &str) -> Option<VCInstance> {
    // For MSVC 12 we need to find the Windows 8.1 SDK.
    let vcdir = otry!(get_vc_dir("12.0"));
    let mut tool = otry!(get_instance(VsVers::Vs12, &vcdir, target));
    let sub = otry!(lib_subdir(target));
    let sdk81 = otry!(get_sdk81_dir());
    tool.path.push(sdk81.join("bin").join(sub));
    let sdk_lib = sdk81.join("lib").join("winv6.3");
    tool.libs.push(sdk_lib.join("um").join(sub));
    let sdk_include = sdk81.join("include");
    tool.include.push(sdk_include.join("shared"));
    tool.include.push(sdk_include.join("um"));
    tool.include.push(sdk_include.join("winrt"));
    Some(tool)
}

/// Returns the environment of the Visual Studio 2012 installation, or None if
/// it is not installed.
pub fn find_msvc_11(target: &str) -> Option<VCInstance> {
    // For MSVC 11 we need to find the Windows 8 SDK.
    let vcdir = otry!(get_vc_dir("11.0"));
    let mut tool = otry!(get_instance(VsVers::Vs11, &vcdir, target));
    let sub = otry!(lib_subdir(target));
    let sdk8 = otry!(get_sdk8_dir());
    tool.path.push(sdk8.join("bin").join(sub));
    let sdk_lib = sdk8.join("lib").join("win8");
    tool.libs.push(sdk_lib.join("um").join(sub));
    let sdk_include = sdk8.join("include");
    tool.include.push(sdk_include.join("shared"));
    tool.include.push(sdk_include.join("um"));
    tool.include.push(sdk_include.join("winrt"));
    Some(tool)
}

// Given a possible MSVC installation directory, we look for the linker and
// then add the MSVC library path.
fn get_instance(version: VsVers, path: &Path, target: &str) -> Option<VCInstance> {
    bin_subdir(target)
        .into_iter()
        .map(|(sub, host)| {
            (
                path.join("bin").join(sub).join("link.exe"),
                path.join("bin").join(host),
            )
        })
        .filter(|&(ref path, _)| path.is_file())
        .map(|(_path, host)| {
            let mut tool = VCInstance::new(version, path.to_owned());
            tool.path.push(host);
            tool
        })
        .filter_map(|mut tool| {
            let sub = otry!(vc_lib_subdir(target));
            tool.libs.push(path.join("lib").join(sub));
            tool.include.push(path.join("include"));
            let atlmfc_path = path.join("atlmfc");
            if atlmfc_path.exists() {
                tool.libs.push(atlmfc_path.join("lib").join(sub));
                tool.include.push(atlmfc_path.join("include"));
            }
            Some(tool)
        })
        .next()
}

// To find MSVC we look in a specific registry key for the version we are
// trying to find.
fn get_vc_dir(ver: &str) -> Option<PathBuf> {
    let key = r"SOFTWARE\Microsoft\VisualStudio\SxS\VC7";
    let key = otry!(LOCAL_MACHINE.open(key.as_ref()).ok());
    let path = otry!(key.query_str(ver).ok());
    Some(path.into())
}

// To find the Universal CRT we look in a specific registry key for where
// all the Universal CRTs are located and then sort them asciibetically to
// find the newest version. While this sort of sorting isn't ideal,  it is
// what vcvars does so that's good enough for us.
//
// Returns a pair of (root, version) for the ucrt dir if found
fn get_ucrt_dir() -> Option<(PathBuf, String)> {
    let key = r"SOFTWARE\Microsoft\Windows Kits\Installed Roots";
    let key = otry!(LOCAL_MACHINE.open(key.as_ref()).ok());
    let root = otry!(key.query_str("KitsRoot10").ok());
    let readdir = otry!(Path::new(&root).join("lib").read_dir().ok());
    let max_libdir = otry!(
        readdir
            .filter_map(|dir| dir.ok())
            .map(|dir| dir.path())
            .filter(|dir| dir
                .components()
                .last()
                .and_then(|c| c.as_os_str().to_str())
                .map(|c| c.starts_with("10.") && dir.join("ucrt").is_dir())
                .unwrap_or(false))
            .max()
    );
    let version = max_libdir.components().last().unwrap();
    let version = version.as_os_str().to_str().unwrap().to_string();
    Some((root.into(), version))
}

// Vcvars finds the correct version of the Windows 10 SDK by looking
// for the include `um\Windows.h` because sometimes a given version will
// only have UCRT bits without the rest of the SDK. Since we only care about
// libraries and not includes, we instead look for `um\x64\kernel32.lib`.
// Since the 32-bit and 64-bit libraries are always installed together we
// only need to bother checking x64, making this code a tiny bit simpler.
// Like we do for the Universal CRT, we sort the possibilities
// asciibetically to find the newest one as that is what vcvars does.
fn get_sdk10_dir() -> Option<(PathBuf, String)> {
    let key = r"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v10.0";
    let key = otry!(LOCAL_MACHINE.open(key.as_ref()).ok());
    let root = otry!(key.query_str("InstallationFolder").ok());
    let readdir = otry!(Path::new(&root).join("lib").read_dir().ok());
    let mut dirs = readdir
        .filter_map(|dir| dir.ok())
        .map(|dir| dir.path())
        .collect::<Vec<_>>();
    dirs.sort();
    let dir = otry!(
        dirs.into_iter()
            .rev()
            .filter(|dir| dir.join("um").join("x64").join("kernel32.lib").is_file())
            .next()
    );
    let version = dir.components().last().unwrap();
    let version = version.as_os_str().to_str().unwrap().to_string();
    Some((root.into(), version))
}

// Interestingly there are several subdirectories, `win7` `win8` and
// `winv6.3`. Vcvars seems to only care about `winv6.3` though, so the same
// applies to us. Note that if we were targetting kernel mode drivers
// instead of user mode applications, we would care.
fn get_sdk81_dir() -> Option<PathBuf> {
    let key = r"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.1";
    let key = otry!(LOCAL_MACHINE.open(key.as_ref()).ok());
    let root = otry!(key.query_str("InstallationFolder").ok());
    Some(root.into())
}

fn get_sdk8_dir() -> Option<PathBuf> {
    let key = r"SOFTWARE\Microsoft\Microsoft SDKs\Windows\v8.0";
    let key = otry!(LOCAL_MACHINE.open(key.as_ref()).ok());
    let root = otry!(key.query_str("InstallationFolder").ok());
    Some(root.into())
}

const PROCESSOR_ARCHITECTURE_INTEL: u16 = 0;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
const X86: u16 = PROCESSOR_ARCHITECTURE_INTEL;
const X86_64: u16 = PROCESSOR_ARCHITECTURE_AMD64;

// When choosing the tool to use, we have to choose the one which matches
// the target architecture. Otherwise we end up in situations where someone
// on 32-bit Windows is trying to cross compile to 64-bit and it tries to
// invoke the native 64-bit compiler which won't work.
//
// For the return value of this function, the first member of the tuple is
// the folder of the tool we will be invoking, while the second member is
// the folder of the host toolchain for that tool which is essential when
// using a cross linker. We return a Vec since on x64 there are often two
// linkers that can target the architecture we desire. The 64-bit host
// linker is preferred, and hence first, due to 64-bit allowing it more
// address space to work with and potentially being faster.
fn bin_subdir(target: &str) -> Vec<(&'static str, &'static str)> {
    let arch = target.split('-').next().unwrap();
    match (arch, host_arch()) {
        ("i586", X86) | ("i686", X86) => vec![("", "")],
        ("i586", X86_64) | ("i686", X86_64) => vec![("amd64_x86", "amd64"), ("", "")],
        ("x86_64", X86) => vec![("x86_amd64", "")],
        ("x86_64", X86_64) => vec![("amd64", "amd64"), ("x86_amd64", "")],
        ("arm", X86) => vec![("x86_arm", "")],
        ("arm", X86_64) => vec![("amd64_arm", "amd64"), ("x86_arm", "")],
        _ => vec![],
    }
}

fn lib_subdir(target: &str) -> Option<&'static str> {
    let arch = target.split('-').next().unwrap();
    match arch {
        "i586" | "i686" => Some("x86"),
        "x86_64" => Some("x64"),
        "arm" => Some("arm"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

// MSVC's x86 libraries are not in a subfolder
fn vc_lib_subdir(target: &str) -> Option<&'static str> {
    let arch = target.split('-').next().unwrap();
    match arch {
        "i586" | "i686" => Some(""),
        "x86_64" => Some("amd64"),
        "arm" => Some("arm"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

#[allow(bad_style)]
fn host_arch() -> u16 {
    type DWORD = u32;
    type WORD = u16;
    type LPVOID = *mut u8;
    type DWORD_PTR = usize;

    #[repr(C)]
    struct SYSTEM_INFO {
        wProcessorArchitecture: WORD,
        _wReserved: WORD,
        _dwPageSize: DWORD,
        _lpMinimumApplicationAddress: LPVOID,
        _lpMaximumApplicationAddress: LPVOID,
        _dwActiveProcessorMask: DWORD_PTR,
        _dwNumberOfProcessors: DWORD,
        _dwProcessorType: DWORD,
        _dwAllocationGranularity: DWORD,
        _wProcessorLevel: WORD,
        _wProcessorRevision: WORD,
    }

    extern "system" {
        fn GetNativeSystemInfo(lpSystemInfo: *mut SYSTEM_INFO);
    }

    unsafe {
        let mut info = mem::zeroed();
        GetNativeSystemInfo(&mut info);
        info.wProcessorArchitecture
    }
}

// Given a registry key, look at all the sub keys and find the one which has
// the maximal numeric value.
//
// Returns the name of the maximal key as well as the opened maximal key.
fn max_version(key: &RegistryKey) -> Option<(OsString, RegistryKey)> {
    let mut max_vers = 0;
    let mut max_key = None;
    for subkey in key.iter().filter_map(|k| k.ok()) {
        let val = subkey
            .to_str()
            .and_then(|s| s.trim_left_matches("v").replace(".", "").parse().ok());
        let val = match val {
            Some(s) => s,
            None => continue,
        };
        if val > max_vers {
            if let Ok(k) = key.open(&subkey) {
                max_vers = val;
                max_key = Some((subkey, k));
            }
        }
    }
    max_key
}

fn has_msbuild_version(version: &str) -> bool {
    match version {
        "15.0" => {
            find_msbuild_vs15("x86_64-pc-windows-msvc").is_some()
                || find_msbuild_vs15("i686-pc-windows-msvc").is_some()
        }
        "12.0" | "14.0" => LOCAL_MACHINE
            .open(&OsString::from(format!(
                "SOFTWARE\\Microsoft\\MSBuild\\ToolsVersions\\{}",
                version
            )))
            .is_ok(),
        _ => false,
    }
}

fn find_devenv(target: &str) -> Option<Tool> {
    find_devenv_vs15(&target)
}

fn find_devenv_vs15(target: &str) -> Option<Tool> {
    let key = r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\SxS\VS7";
    LOCAL_MACHINE
        .open(key.as_ref())
        .ok()
        .and_then(|key| key.query_str("15.0").ok())
        .map(|path| {
            let path = PathBuf::from(path).join(r"Common7\IDE\devenv.exe");
            let mut tool = Tool::new(path);
            if target.contains("x86_64") {
                tool.env.push(("Platform".into(), "X64".into()));
            }
            tool
        })
}

// see http://stackoverflow.com/questions/328017/path-to-msbuild
fn find_msbuild(target: &str) -> Option<Tool> {
    // VS 15 (2017) changed how to locate msbuild
    if let Some(r) = find_msbuild_vs15(target) {
        return Some(r);
    } else {
        find_old_msbuild(target)
    }
}

fn find_msbuild_vs15(target: &str) -> Option<Tool> {
    // Seems like this could also go through SetupConfiguration,
    // or that find_msvc_15 could just use this registry key
    // instead of the COM interface.
    let key = r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\SxS\VS7";
    LOCAL_MACHINE
        .open(key.as_ref())
        .ok()
        .and_then(|key| key.query_str("15.0").ok())
        .map(|path| {
            let path = PathBuf::from(path).join(r"MSBuild\15.0\Bin\MSBuild.exe");
            let mut tool = Tool::new(path);
            if target.contains("x86_64") {
                tool.env.push(("Platform".into(), "X64".into()));
            }
            tool
        })
}

fn find_old_msbuild(target: &str) -> Option<Tool> {
    let key = r"SOFTWARE\Microsoft\MSBuild\ToolsVersions";
    LOCAL_MACHINE
        .open(key.as_ref())
        .ok()
        .and_then(|key| {
            max_version(&key).and_then(|(_vers, key)| key.query_str("MSBuildToolsPath").ok())
        })
        .map(|path| {
            let mut path = PathBuf::from(path);
            path.push("MSBuild.exe");
            let mut tool = Tool::new(path);
            if target.contains("x86_64") {
                tool.env.push(("Platform".into(), "X64".into()));
            }
            tool
        })
}
