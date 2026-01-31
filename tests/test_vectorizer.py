"""
Tests for the behavior vectorizer.
"""

import pytest
import time
from src.models import BehaviorTrace, ToolInvocation, FileAccess, NetworkCall, DecisionCycle
from src.vectorizer import BehaviorVectorizer


@pytest.fixture
def vectorizer():
    return BehaviorVectorizer()


@pytest.fixture
def sample_trace():
    """Create a sample behavior trace for testing."""
    start = time.time()
    
    trace = BehaviorTrace(
        run_id="test-001",
        start_time=start,
        end_time=start + 10,
        stdout_line_count=50,
        stderr_line_count=5,
        exit_code=0,
    )
    
    # Add tool invocations
    trace.tool_invocations = [
        ToolInvocation("read", start + 1, 100, True, 2, ["string"]),
        ToolInvocation("write", start + 2, 150, True, 3, ["string", "string"]),
        ToolInvocation("exec", start + 3, 500, True, 1, ["string"]),
        ToolInvocation("read", start + 4, 80, True, 2, ["string"]),
        ToolInvocation("write", start + 5, 120, True, 2, ["string"]),
    ]
    
    # Add file accesses
    trace.file_accesses = [
        FileAccess("~/file1.txt", "read", start + 1, 1024),
        FileAccess("~/file2.txt", "write", start + 2, 2048),
        FileAccess("~/file1.txt", "read", start + 4, 1024),
    ]
    
    # Add network calls
    trace.network_calls = [
        NetworkCall("api", "GET", start + 3, 200, "2xx"),
        NetworkCall("api", "POST", start + 4, 300, "2xx"),
    ]
    
    # Add decision cycles
    trace.decision_cycles = [
        DecisionCycle(1, start, start + 3, 3, 0, 0),
        DecisionCycle(2, start + 3, start + 6, 2, 1, 0),
    ]
    
    return trace


def test_vectorize_basic(vectorizer, sample_trace):
    """Test basic vectorization."""
    vector = vectorizer.vectorize(sample_trace)
    
    assert vector is not None
    assert len(vector.tool_sequence) == 5
    assert vector.tool_frequency == {"read": 2, "write": 2, "exec": 1}


def test_tool_transitions(vectorizer, sample_trace):
    """Test tool transition tracking."""
    vector = vectorizer.vectorize(sample_trace)
    
    # read -> write, write -> exec, exec -> read, read -> write
    assert "read" in vector.tool_transitions
    assert "write" in vector.tool_transitions["read"]


def test_timing_features(vectorizer, sample_trace):
    """Test timing feature extraction."""
    vector = vectorizer.vectorize(sample_trace)
    
    assert vector.total_duration_ms > 0
    assert vector.mean_tool_duration_ms > 0


def test_decision_features(vectorizer, sample_trace):
    """Test decision feature extraction."""
    vector = vectorizer.vectorize(sample_trace)
    
    assert vector.total_cycles == 2
    assert vector.total_retries == 1
    assert vector.retry_rate == 0.5


def test_file_features(vectorizer, sample_trace):
    """Test file access feature extraction."""
    vector = vectorizer.vectorize(sample_trace)
    
    assert vector.unique_paths_accessed == 2
    assert vector.file_op_frequency == {"read": 2, "write": 1}


def test_network_features(vectorizer, sample_trace):
    """Test network feature extraction."""
    vector = vectorizer.vectorize(sample_trace)
    
    assert vector.network_call_count == 2
    assert vector.error_rate == 0.0


def test_output_features(vectorizer, sample_trace):
    """Test output feature extraction."""
    vector = vectorizer.vectorize(sample_trace)
    
    assert vector.stdout_lines == 50
    assert vector.stderr_lines == 5
    assert 0 < vector.stderr_ratio < 1


def test_empty_trace(vectorizer):
    """Test vectorization of empty trace."""
    trace = BehaviorTrace(
        run_id="empty",
        start_time=time.time(),
        end_time=time.time() + 1,
    )
    
    vector = vectorizer.vectorize(trace)
    
    assert vector.tool_sequence == []
    assert vector.tool_frequency == {}


def test_merge_vectors(vectorizer, sample_trace):
    """Test vector merging."""
    v1 = vectorizer.vectorize(sample_trace)
    v2 = vectorizer.vectorize(sample_trace)
    
    merged = vectorizer.merge_vectors([v1, v2])
    
    assert merged is not None
    assert len(merged.tool_frequency) > 0


def test_variance_bounds(vectorizer, sample_trace):
    """Test variance bounds computation."""
    vectors = [vectorizer.vectorize(sample_trace) for _ in range(5)]
    
    bounds = vectorizer.compute_variance_bounds(vectors)
    
    assert len(bounds) > 0
    assert 'mean_tool_duration_ms' in bounds
    assert 'min' in bounds['mean_tool_duration_ms']
    assert 'max' in bounds['mean_tool_duration_ms']
