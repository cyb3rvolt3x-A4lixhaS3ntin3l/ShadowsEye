"""
Task Queue Engine - Asynchronous task execution with worker pool
Handles concurrent OSINT scans and tool executions
"""

import threading
import queue
import time
from datetime import datetime
from typing import Callable, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, Future


class TaskQueue:
    """Asynchronous task queue with worker pool"""
    
    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.task_queue = queue.Queue()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_tasks: Dict[str, Dict] = {}
        self.completed_tasks: Dict[str, Dict] = {}
        self.failed_tasks: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        self._shutdown = False
        
    def submit(self, 
               task_id: str,
               func: Callable,
               args: tuple = (),
               kwargs: dict = None,
               callback: Callable = None,
               timeout: int = 300) -> str:
        """
        Submit a task for async execution
        
        Args:
            task_id: Unique task identifier
            func: Function to execute
            args: Positional arguments for func
            kwargs: Keyword arguments for func
            callback: Function to call on completion
            timeout: Maximum execution time in seconds
            
        Returns:
            task_id
        """
        if kwargs is None:
            kwargs = {}
        
        task_info = {
            'task_id': task_id,
            'func': func.__name__,
            'args': args,
            'kwargs': kwargs,
            'callback': callback,
            'timeout': timeout,
            'status': 'pending',
            'submitted_at': datetime.utcnow().isoformat(),
            'started_at': None,
            'completed_at': None,
            'result': None,
            'error': None
        }
        
        with self._lock:
            self.active_tasks[task_id] = task_info
        
        # Submit to executor
        future = self.executor.submit(self._execute_task, task_info)
        task_info['future'] = future
        
        return task_id
    
    def _execute_task(self, task_info: Dict) -> Any:
        """Execute a single task with timeout handling"""
        task_id = task_info['task_id']
        
        try:
            # Update status
            with self._lock:
                task_info['status'] = 'running'
                task_info['started_at'] = datetime.utcnow().isoformat()
            
            # Execute function with timeout
            func = task_info['kwargs'].pop('_func', None)
            if func is None:
                # Find function by name from kwargs
                raise ValueError("Function not provided")
            
            result = func(*task_info['args'], **task_info['kwargs'])
            
            # Success
            with self._lock:
                task_info['status'] = 'completed'
                task_info['completed_at'] = datetime.utcnow().isoformat()
                task_info['result'] = result
                self.completed_tasks[task_id] = task_info.copy()
                self.active_tasks.pop(task_id, None)
            
            # Call callback if provided
            if task_info['callback']:
                try:
                    task_info['callback'](task_id, result, None)
                except Exception as e:
                    pass  # Ignore callback errors
            
            return result
            
        except Exception as e:
            # Failure
            with self._lock:
                task_info['status'] = 'failed'
                task_info['completed_at'] = datetime.utcnow().isoformat()
                task_info['error'] = str(e)
                self.failed_tasks[task_id] = task_info.copy()
                self.active_tasks.pop(task_id, None)
            
            # Call callback with error
            if task_info['callback']:
                try:
                    task_info['callback'](task_id, None, str(e))
                except Exception:
                    pass
            
            raise
    
    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Get current status of a task"""
        with self._lock:
            if task_id in self.active_tasks:
                return self.active_tasks[task_id].copy()
            elif task_id in self.completed_tasks:
                return self.completed_tasks[task_id].copy()
            elif task_id in self.failed_tasks:
                return self.failed_tasks[task_id].copy()
        return None
    
    def get_all_active_tasks(self) -> Dict:
        """Get all active tasks"""
        with self._lock:
            return {k: v.copy() for k, v in self.active_tasks.items()}
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending or running task"""
        with self._lock:
            if task_id in self.active_tasks:
                task_info = self.active_tasks[task_id]
                future = task_info.get('future')
                if future and not future.done():
                    future.cancel()
                    task_info['status'] = 'cancelled'
                    return True
        return False
    
    def wait_for_task(self, task_id: str, timeout: int = None) -> Optional[Dict]:
        """Wait for a task to complete"""
        task_info = self.get_task_status(task_id)
        if not task_info:
            return None
        
        future = task_info.get('future')
        if future:
            try:
                future.result(timeout=timeout)
                return self.get_task_status(task_id)
            except Exception as e:
                return {'status': 'failed', 'error': str(e)}
        return task_info
    
    def shutdown(self, wait: bool = True):
        """Shutdown the task queue"""
        self._shutdown = True
        self.executor.shutdown(wait=wait)
    
    def get_stats(self) -> Dict:
        """Get queue statistics"""
        with self._lock:
            return {
                'active': len(self.active_tasks),
                'completed': len(self.completed_tasks),
                'failed': len(self.failed_tasks),
                'max_workers': self.max_workers,
                'queue_size': self.task_queue.qsize() if hasattr(self.task_queue, 'qsize') else 0
            }


# Global task queue instance
global_task_queue = TaskQueue(max_workers=5)


def run_async(func: Callable, *args, **kwargs) -> str:
    """Helper to run a function asynchronously"""
    import uuid
    task_id = str(uuid.uuid4())
    kwargs['_func'] = func
    global_task_queue.submit(task_id, func, args=args, kwargs=kwargs)
    return task_id
