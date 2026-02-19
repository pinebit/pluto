//! Validator client connectivity tests.

use std::{collections::HashMap, io::Write, sync::mpsc, time::Duration};

use clap::Args;
use rand::Rng;
use tokio::{
    net::TcpStream,
    time::{Instant, timeout},
};

use super::{
    AllCategoriesResult, TestCaseName, TestCategory, TestCategoryResult, TestConfigArgs,
    TestResult, TestVerdict, calculate_score, evaluate_highest_rtt, evaluate_rtt, filter_tests,
    publish_result_to_obol_api, sort_tests, write_result_to_file, write_result_to_writer,
};
use crate::{duration::Duration as CliDuration, error::Result};

// Thresholds (from Go implementation)
const THRESHOLD_MEASURE_AVG: Duration = Duration::from_millis(50);
const THRESHOLD_MEASURE_POOR: Duration = Duration::from_millis(240);
const THRESHOLD_LOAD_AVG: Duration = Duration::from_millis(50);
const THRESHOLD_LOAD_POOR: Duration = Duration::from_millis(240);

/// Arguments for the validator test command.
#[derive(Args, Clone, Debug)]
pub struct TestValidatorArgs {
    #[command(flatten)]
    pub test_config: TestConfigArgs,

    /// Listening address (ip and port) for validator-facing traffic.
    #[arg(
        long = "validator-api-address",
        default_value = "127.0.0.1:3600",
        help = "Listening address (ip and port) for validator-facing traffic proxying the beacon-node API."
    )]
    pub api_address: String,

    /// Time to keep running the load tests.
    #[arg(
        long = "load-test-duration",
        default_value = "5s",
        value_parser = humantime::parse_duration,
        help = "Time to keep running the load tests. For each second a new continuous ping instance is spawned."
    )]
    pub load_test_duration: Duration,
}

/// Runs the validator client tests.
pub async fn run(args: TestValidatorArgs, writer: &mut dyn Write) -> Result<TestCategoryResult> {
    tracing::info!("Starting validator client test");

    let start_time = Instant::now();

    // Get and filter test cases
    let all_test_cases = HashMap::from([
        (TestCaseName::new("Ping", 1), ()),
        (TestCaseName::new("PingMeasure", 2), ()),
        (TestCaseName::new("PingLoad", 3), ()),
    ]);
    let mut queued_tests = filter_tests(&all_test_cases, args.test_config.test_cases.as_deref());

    if queued_tests.is_empty() {
        return Err(crate::error::CliError::Other(
            "test case not supported".into(),
        ));
    }

    sort_tests(&mut queued_tests);

    // Run tests with timeout
    let test_results = tokio::time::timeout(args.test_config.timeout, async {
        let mut results = Vec::new();
        for test in queued_tests.iter() {
            let result = match test.name.as_str() {
                "Ping" => ping_test(&args).await,
                "PingMeasure" => ping_measure_test(&args).await,
                "PingLoad" => ping_load_test(&args).await,
                _ => TestResult::new(&test.name).fail(std::io::Error::other("unknown test")),
            };
            results.push(result);
        }
        results
    })
    .await
    .unwrap_or_else(|_| {
        vec![TestResult::new("Timeout").fail(std::io::Error::other("timeout interrupted"))]
    });
    let score = calculate_score(&test_results);

    let mut res = TestCategoryResult::new(TestCategory::Validator);
    res.targets.insert(args.api_address.clone(), test_results);
    res.execution_time = Some(CliDuration::new(start_time.elapsed()));
    res.score = Some(score);

    if !args.test_config.quiet {
        write_result_to_writer(&res, writer)?;
    }

    if !args.test_config.output_json.is_empty() {
        write_result_to_file(&res, args.test_config.output_json.as_ref()).await?;
    }

    if args.test_config.publish {
        let all = AllCategoriesResult {
            validator: Some(res.clone()),
            ..Default::default()
        };
        publish_result_to_obol_api(
            all,
            &args.test_config.publish_addr,
            &args.test_config.publish_private_key_file,
        )
        .await?;
    }

    Ok(res)
}

async fn ping_test(args: &TestValidatorArgs) -> TestResult {
    let mut result = TestResult::new("Ping");

    match timeout(
        Duration::from_secs(1),
        TcpStream::connect(&args.api_address),
    )
    .await
    {
        Ok(Ok(_conn)) => {
            result.verdict = TestVerdict::Ok;
        }
        Ok(Err(e)) => {
            return result.fail(e);
        }
        Err(_) => {
            return result.fail(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection timeout",
            ));
        }
    }

    result
}

async fn ping_measure_test(args: &TestValidatorArgs) -> TestResult {
    let mut result = TestResult::new("PingMeasure");
    let before = Instant::now();

    match timeout(
        Duration::from_secs(1),
        TcpStream::connect(&args.api_address),
    )
    .await
    {
        Ok(Ok(_conn)) => {
            let rtt = before.elapsed();
            result = evaluate_rtt(rtt, result, THRESHOLD_MEASURE_AVG, THRESHOLD_MEASURE_POOR);
        }
        Ok(Err(e)) => {
            return result.fail(e);
        }
        Err(_) => {
            return result.fail(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connection timeout",
            ));
        }
    }

    result
}

async fn ping_load_test(args: &TestValidatorArgs) -> TestResult {
    tracing::info!(
        duration = ?args.load_test_duration,
        target = %args.api_address,
        "Running ping load tests..."
    );

    let mut result = TestResult::new("PingLoad");

    let (tx, rx) = mpsc::channel::<Duration>();
    let address = args.api_address.clone();
    let duration = args.load_test_duration;

    let handle = tokio::spawn(async move {
        let start = Instant::now();
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        while start.elapsed() < duration {
            interval.tick().await;

            let tx = tx.clone();
            let addr = address.clone();
            let remaining = duration.saturating_sub(start.elapsed());

            tokio::spawn(async move {
                ping_continuously(addr, tx, remaining).await;
            });
        }
    });

    let _ = handle.await;

    let mut rtts = Vec::new();
    while let Ok(rtt) = rx.try_recv() {
        rtts.push(rtt);
    }

    tracing::info!(target = %args.api_address, "Ping load tests finished");

    result = evaluate_highest_rtt(rtts, result, THRESHOLD_LOAD_AVG, THRESHOLD_LOAD_POOR);

    result
}

async fn ping_continuously(address: String, tx: mpsc::Sender<Duration>, max_duration: Duration) {
    let start = Instant::now();

    while start.elapsed() < max_duration {
        let before = Instant::now();

        match timeout(Duration::from_secs(1), TcpStream::connect(&address)).await {
            Ok(Ok(_conn)) => {
                let rtt = before.elapsed();
                if tx.send(rtt).is_err() {
                    return;
                }
            }
            _ => return,
        }

        let sleep_ms = rand::thread_rng().gen_range(0..100);
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }
}
