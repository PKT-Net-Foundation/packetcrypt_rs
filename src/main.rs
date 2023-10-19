// SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
use anyhow::{Result};
use clap::{App, Arg, SubCommand};
use log::warn;
use packetcrypt_annmine::annmine;
use packetcrypt_util::{util};
use std::path;
#[cfg(not(target_os = "windows"))]
use tokio::signal::unix::{signal, SignalKind};

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(feature = "leak_detect")]
mod alloc;

#[cfg(feature = "leak_detect")]
async fn leak_detect() -> Result<()> {
    let al = alloc::alloc_init().await?;
    let mut s = signal(SignalKind::user_defined1())?;
    tokio::spawn(async move {
        loop {
            s.recv().await;
            let outfile = format!("packetcrypt_memory_{}.txt", util::now_ms());
            println!("Got SIGUSR1, writing memory trace to: [{}]", outfile);
            if let Err(e) = al.write_mem_allocations(outfile).await {
                println!("Error writing memory trace [{:?}]", e);
            }
        }
    });
    Ok(())
}

#[cfg(not(feature = "leak_detect"))]
async fn leak_detect() -> Result<()> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
async fn exiter() -> Result<()> {
    let mut s = signal(SignalKind::user_defined2())?;
    tokio::spawn(async move {
        s.recv().await;
        println!("Got SIGUSR2, calling process::exit()");
        std::process::exit(252);
    });
    Ok(())
}

#[cfg(target_os = "windows")]
async fn exiter() -> Result<()> {
    Ok(())
}
const DEFAULT_ADDR: &str = "pkt1q6hqsqhqdgqfd8t3xwgceulu7k9d9w5t2amath0qxyfjlvl3s3u4sjza2g2";

fn warn_if_addr_default(payment_addr: &str) -> &str {
    if payment_addr == DEFAULT_ADDR {
        warn!(
            "--paymentaddr was not specified, coins will be mined for {}",
            DEFAULT_ADDR
        );
    }

    payment_addr
}
async fn ann_load_config(
    pools: Vec<String>,
    threads: usize,
    payment_addr: String,
    uploaders: usize,
    upload_timeout: usize,
    mine_old_anns: i32,
    config_json_path: String
) -> Result<annmine::AnnMineExternalConfig> {
    let defaults = CliParamDefault { ..Default::default() };

    let mut config = annmine::AnnMineExternalConfig {
        pools: Some(pools.clone()),
        threads: Some(threads),
        payment_addr: Some(payment_addr.clone()),
        uploaders: Some(uploaders),
        upload_timeout: Some(upload_timeout),
        mine_old_anns: Some(mine_old_anns),
    };

    if !config_json_path.is_empty() {
        //let cfg: annmine::AnnMineExternalConfig;
        let json: String;

        if config_json_path.contains("http://") || config_json_path.contains("https://") {
            let res = reqwest::get(&config_json_path).await?;
            match res.status() {
                reqwest::StatusCode::OK => {
                    json = res.text().await.ok().expect("Could not read response body");
                },
                st => panic!("Failed to load config.json. Status code was {:?}", st),
            };  
        } else {    
            let file = path::Path::new(config_json_path.as_str());
            json = tokio::fs::read_to_string(file).await.ok().expect("Could not read file");
        }

        match serde_json::from_str::<annmine::AnnMineExternalConfig>(json.as_str()){
            Result::Ok(parsed) => {

                if pools.len() == 0 {
                    if let Some(p) = parsed.pools {
                        config.pools = Some(p);
                    }
                }
                if threads == defaults.ann_threads {
                    if let Some(t) = parsed.threads {
                        config.threads = Some(t);
                    }
                }
                if payment_addr == defaults.ann_payment_addr {
                    if let Some(a) = parsed.payment_addr {
                        config.payment_addr = Some(a);
                    } 
                }
                if uploaders == defaults.ann_uploaders {
                    if let Some(u) = parsed.uploaders {
                        config.uploaders = Some(u);
                    }
                }
                if upload_timeout == defaults.ann_upload_timeout {
                    if let Some(ut) = parsed.upload_timeout {
                        config.upload_timeout = Some(ut);
                    } 
                }
                if mine_old_anns == defaults.ann_mine_old {
                    if let Some(m) = parsed.mine_old_anns {
                        config.mine_old_anns = Some(m);
                    }
                }
            },
            Result::Err(err) => {panic!("Unable to parse config.json {}", err)}
        };
    }

    config.print();

    Ok(config)
}

async fn ann_main(
    config: annmine::AnnMineExternalConfig
) -> Result<()> {  
    let am = annmine::new(annmine::AnnMineCfg {
        pools: config.pools.unwrap(),
        miner_id: util::rand_u32(),
        workers: config.threads.unwrap(),
        uploaders: config.uploaders.unwrap(),
        pay_to: config.payment_addr.unwrap(),
        upload_timeout: config.upload_timeout.unwrap(),
        mine_old_anns: config.mine_old_anns.unwrap(),
    })
    .await?;
    annmine::start(&am).await?;

    util::sleep_forever().await
}

macro_rules! get_strs {
    ($m:ident, $s:expr) => {
        if let Some(x) = $m.values_of($s) {
            x.map(|x| x.to_string()).collect::<Vec<String>>()
        } else {
            return Ok(());
        }
    };
}
macro_rules! get_str {
    ($m:ident, $s:expr) => {
        if let Some(x) = $m.value_of($s) {
            x
        } else {
            return Ok(());
        }
    };
}
macro_rules! get_usize {
    ($m:ident, $s:expr) => {
        get_num!($m, $s, usize)
    };
}
macro_rules! get_num {
    ($m:ident, $s:expr, $n:ident) => {{
        let s = get_str!($m, $s);
        if let Ok(u) = s.parse::<$n>() {
            u
        } else {
            println!("Unable to parse argument {} as number [{}]", $s, s);
            return Ok(());
        }
    }};
}

async fn async_main(matches: clap::ArgMatches<'_>) -> Result<()> {
    leak_detect().await?;
    exiter().await?;
    packetcrypt_sys::init();
    util::setup_env(matches.occurrences_of("v")).await?;
    if let Some(ann) = matches.subcommand_matches("ann") {
        // ann miner
        let pools = if ann.is_present("pools") {
            get_strs!(ann, "pools")
        } else {
            Vec::new()
        }.to_owned();
        let payment_addr = get_str!(ann, "paymentaddr");
        let threads = get_usize!(ann, "threads");
        let uploaders = get_usize!(ann, "uploaders");
        let upload_timeout = get_usize!(ann, "uploadtimeout");
        let mine_old_anns = get_num!(ann, "mineold", i32);
        let config_json_path = if ann.is_present("config") {
            get_str!(ann, "config")
        } else {
            ""
        }.to_owned();

        let mut config = ann_load_config(
            pools,
            threads, 
            payment_addr.to_string(), 
            uploaders, 
            upload_timeout, 
            mine_old_anns, 
            config_json_path
        ).await?;

        // TODO: There has to be a better way to avoid moving `config.payment_addr`
        // when calling `warn_if_addr_default` here...
        config.payment_addr = Some(warn_if_addr_default(&config.payment_addr.unwrap()).to_string());

        ann_main(config)
        .await?;
    }
    Ok(())
}

struct CliParamDefault {
    ann_threads: usize,
    ann_uploaders: usize,
    ann_payment_addr: String,
    ann_upload_timeout: usize,
    ann_mine_old: i32,
}
impl Default for CliParamDefault {
    fn default() -> CliParamDefault {
        CliParamDefault {
            ann_threads: num_cpus::get(),
            ann_uploaders: 10,
            ann_payment_addr: String::from(DEFAULT_ADDR),
            ann_upload_timeout: 30,
            ann_mine_old: -1
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let defaults = CliParamDefault { ..Default::default() };
    let cpus_str = defaults.ann_threads.to_string();  //format!("{}", num_cpus::get());
    let ann_uploaders = defaults.ann_uploaders.to_string();
    let ann_upload_timeout = defaults.ann_upload_timeout.to_string();
    let ann_payment_addr = defaults.ann_payment_addr.to_string();
    let ann_mine_old = defaults.ann_mine_old.to_string();

    let matches = App::new("packetcrypt")
        .version(util::version())
        .author("Caleb James DeLisle <cjd@cjdns.fr>")
        .about("Bandwidth hard proof of work algorithm")
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .arg(
            Arg::with_name("v")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Verbose logging"),
        )
        .subcommand(
            SubCommand::with_name("ann")
                .about("Run announcement miner")
                .arg(
                    Arg::with_name("threads")
                        .short("t")
                        .long("threads")
                        .help("Number of threads to mine with")
                        .default_value(&cpus_str)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("uploaders")
                        .short("U")
                        .long("uploaders")
                        .help("Max concurrent uploads (per pool handler)")
                        .default_value(&ann_uploaders)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("uploadtimeout")
                        .short("T")
                        .long("uploadtimeout")
                        .help("How long to wait for a reply before aborting an upload")
                        .default_value(&ann_upload_timeout)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("paymentaddr")
                        .short("p")
                        .long("paymentaddr")
                        .help("Address to request payment for mining")
                        .default_value(&ann_payment_addr),
                )
                .arg(
                    Arg::with_name("mineold")
                        .short("m")
                        .long("mineold")
                        .help("how many blocks old to mine annoucements, -1 to let the pool decide")
                        .default_value(&ann_mine_old),
                )
                .arg(
                    Arg::with_name("pools")
                        .help("The pools to mine in")
                        .required_unless("config")
                        .min_values(1),
                )
                .arg(
                    Arg::with_name("config")
                        .short("c")
                        .long("config")
                        .help("Path to config.json")
                        .takes_value(true),
                ),
                
        )
        .get_matches();

    async_main(matches).await
}
