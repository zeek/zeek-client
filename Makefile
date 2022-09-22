.PHONY: test
test:
	cd tests && python -m unittest

.PHONY: test-coverage
test-coverage:
	command -v coverage >/dev/null || { echo "Please install coverage via 'pip install coverage'"; exit 1; }
	cd tests \
	    && coverage run --source=../zeekclient -m unittest \
	       test_brokertypes.py \
	       test_config.py \
               test_controller.py \
               test_rendering.py \
	    && coverage report -m
