import pytest
from sentinel.tenancy.temporal_queues import TenantQueueManager, get_task_queue, get_workflow_id
from sentinel.tenancy.context import set_tenant


class TestTenantQueues:
    def test_provision_free(self):
        mgr = TenantQueueManager()
        queue = mgr.provision_queue("t1", "free")
        assert queue.worker_count == 1
        assert queue.max_concurrent_workflows == 2

    def test_provision_pro(self):
        mgr = TenantQueueManager()
        queue = mgr.provision_queue("t1", "pro")
        assert queue.worker_count == 2
        assert queue.max_concurrent_workflows == 5

    def test_provision_enterprise(self):
        mgr = TenantQueueManager()
        queue = mgr.provision_queue("t1", "enterprise")
        assert queue.worker_count == 4
        assert queue.max_concurrent_workflows == 20

    def test_get_task_queue(self):
        set_tenant("acme")
        assert get_task_queue() == "sentinel-acme"

    def test_get_workflow_id(self):
        set_tenant("acme")
        wf_id = get_workflow_id("eng-001")
        assert wf_id == "acme:eng-001"

    def test_list_queues(self):
        mgr = TenantQueueManager()
        mgr.provision_queue("t1", "free")
        mgr.provision_queue("t2", "pro")
        assert len(mgr.list_queues()) == 2

    def test_get_queue(self):
        mgr = TenantQueueManager()
        mgr.provision_queue("t1", "enterprise")
        q = mgr.get_queue("t1")
        assert q is not None
        assert q.queue_name == "sentinel-t1"

    def test_get_queue_missing(self):
        mgr = TenantQueueManager()
        assert mgr.get_queue("nonexistent") is None

    def test_unknown_plan_defaults_to_free(self):
        mgr = TenantQueueManager()
        queue = mgr.provision_queue("t1", "unknown_plan")
        assert queue.worker_count == 1
