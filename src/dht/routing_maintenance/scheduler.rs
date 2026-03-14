//! Background task scheduler for routing maintenance
//!
//! Coordinates periodic maintenance tasks:
//! - Bucket refresh operations
//! - Close group validation
//! - Record republishing
//!
//! Copyright 2024 Saorsa Labs
//! SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

use std::time::{Duration, Instant};

use super::config::MaintenanceConfig;

/// Types of maintenance tasks (routing table only — no record storage)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MaintenanceTask {
    /// Refresh k-buckets
    BucketRefresh,
    /// Validate nodes via close group consensus
    CloseGroupValidation,
}

impl MaintenanceTask {
    /// Get all task types
    #[must_use]
    pub fn all() -> Vec<MaintenanceTask> {
        vec![
            MaintenanceTask::BucketRefresh,
            MaintenanceTask::CloseGroupValidation,
        ]
    }

    /// Get the default interval for this task type
    #[must_use]
    pub fn default_interval(&self, config: &MaintenanceConfig) -> Duration {
        match self {
            MaintenanceTask::BucketRefresh => config.bucket_refresh_interval,
            MaintenanceTask::CloseGroupValidation => Duration::from_secs(300), // Every 5 minutes
        }
    }
}

/// State for a scheduled task
#[derive(Debug, Clone)]
pub struct ScheduledTask {
    /// The task type
    pub task: MaintenanceTask,
    /// Last time this task was executed
    pub last_run: Instant,
    /// Configured interval between runs
    pub interval: Duration,
    /// Number of times the task has run
    pub run_count: u64,
    /// Number of failures
    pub failure_count: u64,
    /// Whether the task is currently running
    pub is_running: bool,
}

impl ScheduledTask {
    /// Create a new scheduled task
    #[must_use]
    pub fn new(task: MaintenanceTask, interval: Duration) -> Self {
        Self {
            task,
            last_run: Instant::now(),
            interval,
            run_count: 0,
            failure_count: 0,
            is_running: false,
        }
    }

    /// Check if this task is due to run
    #[must_use]
    pub fn is_due(&self) -> bool {
        !self.is_running && self.last_run.elapsed() >= self.interval
    }

    /// Mark task as started
    pub fn start(&mut self) {
        self.is_running = true;
    }

    /// Mark task as completed successfully
    pub fn complete(&mut self) {
        self.is_running = false;
        self.last_run = Instant::now();
        self.run_count += 1;
    }

    /// Mark task as failed
    pub fn fail(&mut self) {
        self.is_running = false;
        self.last_run = Instant::now();
        self.failure_count += 1;
    }
}

/// Manages scheduling of maintenance tasks
pub struct MaintenanceScheduler {
    /// Scheduled tasks
    tasks: Vec<ScheduledTask>,
    /// Whether the scheduler is active
    is_active: bool,
}

impl MaintenanceScheduler {
    /// Create a new scheduler with default task configuration
    #[must_use]
    pub fn new(config: MaintenanceConfig) -> Self {
        let mut tasks = Vec::new();

        for task_type in MaintenanceTask::all() {
            let interval = task_type.default_interval(&config);
            tasks.push(ScheduledTask::new(task_type, interval));
        }

        Self {
            tasks,
            is_active: false,
        }
    }

    /// Start the scheduler
    pub fn start(&mut self) {
        self.is_active = true;
    }

    /// Get the next tasks that are due to run
    #[must_use]
    pub fn get_due_tasks(&self) -> Vec<MaintenanceTask> {
        if !self.is_active {
            return Vec::new();
        }

        self.tasks
            .iter()
            .filter(|t| t.is_due())
            .map(|t| t.task)
            .collect()
    }

    /// Mark a task as started
    pub fn mark_started(&mut self, task: MaintenanceTask) {
        if let Some(scheduled) = self.tasks.iter_mut().find(|t| t.task == task) {
            scheduled.start();
        }
    }

    /// Mark a task as completed successfully
    pub fn mark_completed(&mut self, task: MaintenanceTask) {
        if let Some(scheduled) = self.tasks.iter_mut().find(|t| t.task == task) {
            scheduled.complete();
        }
    }

    /// Mark a task as failed
    pub fn mark_failed(&mut self, task: MaintenanceTask) {
        if let Some(scheduled) = self.tasks.iter_mut().find(|t| t.task == task) {
            scheduled.fail();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maintenance_task_all() {
        let all_tasks = MaintenanceTask::all();
        assert_eq!(all_tasks.len(), 2);
    }

    #[test]
    fn test_scheduled_task_new() {
        let task = ScheduledTask::new(MaintenanceTask::BucketRefresh, Duration::from_secs(60));
        assert_eq!(task.run_count, 0);
        assert_eq!(task.failure_count, 0);
        assert!(!task.is_running);
    }

    #[test]
    fn test_scheduled_task_is_due() {
        let mut task = ScheduledTask::new(MaintenanceTask::BucketRefresh, Duration::from_nanos(0));

        assert!(task.is_due());

        task.start();
        assert!(!task.is_due());

        task.complete();
        assert!(task.is_due());
    }

    #[test]
    fn test_scheduled_task_start_complete() {
        let mut task = ScheduledTask::new(
            MaintenanceTask::CloseGroupValidation,
            Duration::from_secs(60),
        );

        task.start();
        assert!(task.is_running);

        task.complete();
        assert!(!task.is_running);
        assert_eq!(task.run_count, 1);
        assert_eq!(task.failure_count, 0);
    }

    #[test]
    fn test_scheduled_task_fail() {
        let mut task = ScheduledTask::new(MaintenanceTask::BucketRefresh, Duration::from_secs(60));

        task.start();
        task.fail();

        assert!(!task.is_running);
        assert_eq!(task.run_count, 0);
        assert_eq!(task.failure_count, 1);
    }

    #[test]
    fn test_scheduler_new() {
        let config = MaintenanceConfig::default();
        let scheduler = MaintenanceScheduler::new(config);

        assert_eq!(scheduler.tasks.len(), 2);
        assert!(!scheduler.is_active);
    }

    #[test]
    fn test_scheduler_start() {
        let config = MaintenanceConfig::default();
        let mut scheduler = MaintenanceScheduler::new(config);

        scheduler.start();
        assert!(scheduler.is_active);
    }

    #[test]
    fn test_scheduler_get_due_tasks() {
        let config = MaintenanceConfig::default();
        let mut scheduler = MaintenanceScheduler::new(config);

        // Not active - no tasks due
        assert!(scheduler.get_due_tasks().is_empty());

        scheduler.start();

        // Set all tasks to have zero interval (for testing)
        for task in &mut scheduler.tasks {
            task.interval = Duration::from_nanos(0);
        }

        let due = scheduler.get_due_tasks();
        assert_eq!(due.len(), 2);
    }

    #[test]
    fn test_scheduler_mark_operations() {
        let config = MaintenanceConfig::default();
        let mut scheduler = MaintenanceScheduler::new(config);

        scheduler.mark_started(MaintenanceTask::BucketRefresh);

        let task = scheduler
            .tasks
            .iter()
            .find(|t| t.task == MaintenanceTask::BucketRefresh)
            .unwrap();
        assert!(task.is_running);

        scheduler.mark_completed(MaintenanceTask::BucketRefresh);

        let task = scheduler
            .tasks
            .iter()
            .find(|t| t.task == MaintenanceTask::BucketRefresh)
            .unwrap();
        assert!(!task.is_running);
        assert_eq!(task.run_count, 1);
    }

    #[test]
    fn test_task_default_intervals() {
        let config = MaintenanceConfig::default();

        let bucket_interval = MaintenanceTask::BucketRefresh.default_interval(&config);
        assert_eq!(bucket_interval, config.bucket_refresh_interval);
    }
}
