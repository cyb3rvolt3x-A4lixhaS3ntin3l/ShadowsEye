#!/usr/bin/env python3
"""
Task Queue Engine - Async job processing with retries, timeouts, and circuit breakers
Uses Redis if available, falls back to in-memory queue for development
"""

import json
import time
import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from dataclasses import dataclass, asdict
import traceback


class JobStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    RETRYING = "retrying"


@dataclass
class Task:
    """Represents a task in the queue"""
    task_id: str
    module_id: str
    target: str
    case_id: int
    user_id: int
    parameters: Dict[str, Any]
    status: JobStatus
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout: int = 60
    priority: int = 5  # 1-10, lower is higher priority
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Task':
        data['status'] = JobStatus(data['status'])
        return cls(**data)


class CircuitBreaker:
    """Circuit breaker pattern for failing modules"""
    
    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failures = {}
        self.last_failure_time = {}
        self.state = {}  # 'closed', 'open', 'half-open'
    
    def record_failure(self, module_id: str):
        """Record a failure for a module"""
        if module_id not in self.failures:
            self.failures[module_id] = 0
            self.state[module_id] = 'closed'
        
        self.failures[module_id] += 1
        self.last_failure_time[module_id] = time.time()
        
        if self.failures[module_id] >= self.failure_threshold:
            self.state[module_id] = 'open'
    
    def record_success(self, module_id: str):
        """Record a success for a module"""
        self.failures[module_id] = 0
        self.state[module_id] = 'closed'
    
    def can_execute(self, module_id: str) -> bool:
        """Check if module can be executed"""
        if module_id not in self.state:
            return True
        
        if self.state[module_id] == 'closed':
            return True
        
        if self.state[module_id] == 'open':
            # Check if recovery timeout has passed
            if time.time() - self.last_failure_time.get(module_id, 0) > self.recovery_timeout:
                self.state[module_id] = 'half-open'
                return True
            return False
        
        if self.state[module_id] == 'half-open':
            return True
        
        return False


class InMemoryQueue:
    """Simple in-memory task queue (fallback when Redis unavailable)"""
    
    def __init__(self):
        self.queue = []
        self.lock = threading.Lock()
        self.subscribers = []
    
    def enqueue(self, task: Task):
        with self.lock:
            self.queue.append(task)
            self.queue.sort(key=lambda t: (t.priority, t.created_at))
            self._notify_subscribers()
    
    def dequeue(self) -> Optional[Task]:
        with self.lock:
            if self.queue:
                return self.queue.pop(0)
            return None
    
    def peek(self) -> Optional[Task]:
        with self.lock:
            return self.queue[0] if self.queue else None
    
    def size(self) -> int:
        with self.lock:
            return len(self.queue)
    
    def _notify_subscribers(self):
        for callback in self.subscribers:
            try:
                callback(len(self.queue))
            except:
                pass
    
    def subscribe(self, callback):
        self.subscribers.append(callback)


class TaskQueueEngine:
    """Main task queue engine with async processing"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.tasks: Dict[str, Task] = {}
        self.queue = InMemoryQueue()
        self.circuit_breaker = CircuitBreaker()
        self.module_executors: Dict[str, Callable] = {}
        self.workers = []
        self.running = False
        self.results_callbacks = []
        self._initialized = True
    
    def register_executor(self, module_id: str, executor: Callable):
        """Register an executor function for a module"""
        self.module_executors[module_id] = executor
    
    def submit_task(self, module_id: str, target: str, case_id: int, user_id: int,
                   parameters: Dict[str, Any] = None, priority: int = 5,
                   timeout: int = 60, max_retries: int = 3) -> str:
        """Submit a new task to the queue"""
        task_id = str(uuid.uuid4())
        
        task = Task(
            task_id=task_id,
            module_id=module_id,
            target=target,
            case_id=case_id,
            user_id=user_id,
            parameters=parameters or {},
            status=JobStatus.QUEUED,
            created_at=datetime.now().isoformat(),
            timeout=timeout,
            max_retries=max_retries,
            priority=priority
        )
        
        self.tasks[task_id] = task
        self.queue.enqueue(task)
        
        return task_id
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a task"""
        task = self.tasks.get(task_id)
        if task:
            return task.to_dict()
        return None
    
    def get_all_tasks(self, case_id: int = None, status: JobStatus = None) -> List[Dict]:
        """Get all tasks, optionally filtered"""
        result = []
        for task in self.tasks.values():
            if case_id and task.case_id != case_id:
                continue
            if status and task.status != status:
                continue
            result.append(task.to_dict())
        return sorted(result, key=lambda t: t['created_at'], reverse=True)
    
    def start_workers(self, num_workers: int = 2):
        """Start worker threads"""
        self.running = True
        for i in range(num_workers):
            worker = threading.Thread(target=self._worker_loop, args=(i,), daemon=True)
            worker.start()
            self.workers.append(worker)
        print(f"[*] Started {num_workers} worker threads")
    
    def stop_workers(self):
        """Stop all workers"""
        self.running = False
        for worker in self.workers:
            worker.join(timeout=5)
        self.workers.clear()
    
    def _worker_loop(self, worker_id: int):
        """Worker loop to process tasks"""
        print(f"[*] Worker {worker_id} started")
        
        while self.running:
            task = self.queue.dequeue()
            
            if not task:
                time.sleep(0.5)
                continue
            
            # Check circuit breaker
            if not self.circuit_breaker.can_execute(task.module_id):
                print(f"[!] Circuit breaker open for {task.module_id}, requeuing task")
                task.status = JobStatus.QUEUED
                self.queue.enqueue(task)
                time.sleep(2)
                continue
            
            # Execute task
            self._execute_task(task, worker_id)
    
    def _execute_task(self, task: Task, worker_id: int):
        """Execute a single task with timeout and error handling"""
        task.status = JobStatus.RUNNING
        task.started_at = datetime.now().isoformat()
        
        executor = self.module_executors.get(task.module_id)
        
        if not executor:
            task.status = JobStatus.FAILED
            task.error = f"No executor registered for module {task.module_id}"
            task.completed_at = datetime.now().isoformat()
            self._notify_result(task)
            return
        
        try:
            # Execute with timeout
            result = [None]
            exception = [None]
            
            def target():
                try:
                    result[0] = executor(task.target)
                except Exception as e:
                    exception[0] = e
            
            thread = threading.Thread(target=target)
            thread.start()
            thread.join(timeout=task.timeout)
            
            if thread.is_alive():
                # Timeout
                task.status = JobStatus.TIMEOUT
                task.error = f"Task timed out after {task.timeout} seconds"
                task.completed_at = datetime.now().isoformat()
                self.circuit_breaker.record_failure(task.module_id)
            elif exception[0]:
                # Exception occurred
                raise exception[0]
            else:
                # Success
                task.result = result[0]
                
                # Check if result indicates partial success
                if isinstance(result[0], dict) and result[0].get('status') == 'error':
                    task.status = JobStatus.PARTIAL
                    task.error = result[0].get('error', 'Unknown error')
                else:
                    task.status = JobStatus.SUCCESS
                
                task.completed_at = datetime.now().isoformat()
                
                if task.status == JobStatus.SUCCESS:
                    self.circuit_breaker.record_success(task.module_id)
                else:
                    self.circuit_breaker.record_failure(task.module_id)
        
        except Exception as e:
            task.error = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
            
            # Retry logic
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.status = JobStatus.RETRYING
                task.started_at = None
                self.queue.enqueue(task)
                print(f"[!] Task {task.task_id} failed, retry {task.retry_count}/{task.max_retries}")
            else:
                task.status = JobStatus.FAILED
                task.completed_at = datetime.now().isoformat()
                self.circuit_breaker.record_failure(task.module_id)
        
        self._notify_result(task)
    
    def _notify_result(self, task: Task):
        """Notify subscribers of task completion"""
        for callback in self.results_callbacks:
            try:
                callback(task)
            except Exception as e:
                print(f"[!] Error in result callback: {e}")
    
    def on_result(self, callback):
        """Register a callback for task completion"""
        self.results_callbacks.append(callback)
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        stats = {
            'total_tasks': len(self.tasks),
            'queued': sum(1 for t in self.tasks.values() if t.status == JobStatus.QUEUED),
            'running': sum(1 for t in self.tasks.values() if t.status == JobStatus.RUNNING),
            'success': sum(1 for t in self.tasks.values() if t.status == JobStatus.SUCCESS),
            'failed': sum(1 for t in self.tasks.values() if t.status == JobStatus.FAILED),
            'partial': sum(1 for t in self.tasks.values() if t.status == JobStatus.PARTIAL),
            'timeout': sum(1 for t in self.tasks.values() if t.status == JobStatus.TIMEOUT),
            'queue_size': self.queue.size(),
            'workers': len(self.workers)
        }
        return stats


# Global instance
task_queue = TaskQueueEngine()


if __name__ == '__main__':
    # Test the task queue
    def mock_executor(target):
        time.sleep(1)
        return {'status': 'success', 'data': f'Result for {target}'}
    
    task_queue.register_executor('test', mock_executor)
    task_queue.start_workers(2)
    
    task_id = task_queue.submit_task('test', 'example.com', 1, 1)
    print(f"Submitted task: {task_id}")
    
    time.sleep(3)
    print(f"Task status: {task_queue.get_task_status(task_id)}")
    print(f"Queue stats: {json.dumps(task_queue.get_queue_stats(), indent=2)}")
    
    task_queue.stop_workers()
