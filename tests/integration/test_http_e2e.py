"""Multi-tenant HTTP integration tests: live API + database required."""
import os
import pytest

pytestmark = pytest.mark.skipif(os.getenv('RUN_INTEGRATION') != '1', reason='RUN_INTEGRATION=1 requires running API')


def test_full_security_workflow():
    from scripts.demo import main
    main()
