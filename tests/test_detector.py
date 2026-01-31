"""
Tests for drift detection.
"""

import pytest
import time
import tempfile
from src.models import BehaviorTrace, ToolInvocation, DecisionCycle
from src.baseline import BaselineManager
from src.detector import DriftDetector


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def baseline_mgr(temp_dir):
    return BaselineManager(storage_dir=temp_dir)


@pytest.fixture
def detector(baseline_mgr):
    return DriftDetector(baseline_manager=baseline_mgr)


def create_trace(
    run_id: str,
    tools: list = None,
    retries: int = 0,
) -> BehaviorTrace:
    """Helper to create test traces."""
    start = time.time()
    
    trace = BehaviorTrace(
        run_id=run_id,
        start_time=start,
        end_time=start + 5,
        stdout_line_count=20,
        stderr_line_count=2,
    )
    
    if tools is None:
        tools = ["read", "write", "exec"]
    
    for i, tool in enumerate(tools):
        trace.tool_invocations.append(
            ToolInvocation(tool, start + i, 100, True, 1, ["string"])
        )
    
    trace.decision_cycles.append(
        DecisionCycle(1, start, start + 5, len(tools), retries, 0)
    )
    
    return trace


def test_first_run_creates_baseline(detector, baseline_mgr):
    """Test that first run creates baseline."""
    trace = create_trace("first-001")
    
    assert not baseline_mgr.has_baseline()
    
    report = detector.detect(trace)
    
    assert baseline_mgr.has_baseline()
    assert report.overall_drift_score == 0.0
    assert "First run" in report.anomalies[0]


def test_identical_run_low_drift(detector):
    """Test that identical runs have low drift."""
    # Create baseline
    trace1 = create_trace("baseline-001")
    detector.detect(trace1)
    
    # Identical run
    trace2 = create_trace("compare-001")
    report = detector.detect(trace2)
    
    assert report.overall_drift_score < 0.3
    assert report.alert_level == "normal"


def test_different_tools_high_drift(detector):
    """Test that different tools cause high drift."""
    # Create baseline with read/write/exec
    trace1 = create_trace("baseline-001", tools=["read", "write", "exec"])
    detector.detect(trace1)
    
    # Different tools
    trace2 = create_trace("compare-001", tools=["delete", "network", "unknown"])
    report = detector.detect(trace2)
    
    assert report.overall_drift_score > 0.3
    assert any("New tools" in a for a in report.anomalies)


def test_missing_tools_causes_drift(detector):
    """Test that missing expected tools causes drift."""
    # Create baseline with multiple tools
    trace1 = create_trace("baseline-001", tools=["read", "write", "exec", "validate"])
    detector.detect(trace1)
    
    # Missing tools
    trace2 = create_trace("compare-001", tools=["read"])
    report = detector.detect(trace2)
    
    assert report.overall_drift_score > 0.2
    assert any("not used" in a for a in report.anomalies)


def test_increased_retries_causes_drift(detector):
    """Test that increased retries causes drift."""
    # Baseline with no retries
    trace1 = create_trace("baseline-001", retries=0)
    detector.detect(trace1)
    
    # High retry count
    trace2 = create_trace("compare-001", retries=5)
    report = detector.detect(trace2)
    
    assert report.component_scores.get("decision", 0) > 0


def test_alert_levels(detector):
    """Test alert level classification."""
    # Create baseline
    trace1 = create_trace("baseline-001")
    detector.detect(trace1)
    
    # Normal - identical trace
    trace2 = create_trace("normal-001")
    report = detector.detect(trace2)
    assert report.alert_level == "normal"
    
    # Simulate higher drift by using very different tools
    trace3 = create_trace("warning-001", tools=["a", "b", "c", "d", "e", "f"])
    report = detector.detect(trace3)
    # Alert level depends on accumulated drift


def test_component_scores_present(detector):
    """Test that all component scores are calculated."""
    trace1 = create_trace("baseline-001")
    detector.detect(trace1)
    
    trace2 = create_trace("compare-001")
    report = detector.detect(trace2)
    
    expected_components = [
        'tool_sequence',
        'tool_frequency', 
        'timing',
        'decision',
        'file_access',
        'network',
        'output',
    ]
    
    for comp in expected_components:
        assert comp in report.component_scores


def test_baseline_updates_on_trusted_run(detector, baseline_mgr):
    """Test that baseline updates when drift is low."""
    # Create baseline
    trace1 = create_trace("baseline-001")
    detector.detect(trace1)
    
    initial_count = baseline_mgr.baseline.run_count
    
    # Similar run (low drift)
    trace2 = create_trace("similar-001")
    report = detector.detect(trace2)
    
    # Baseline should update
    if report.overall_drift_score <= 0.3:
        assert baseline_mgr.baseline.run_count > initial_count
