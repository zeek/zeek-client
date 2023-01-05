.PHONY: all
all:

.PHONY: test
test:
	cd tests && python -m unittest

.PHONY: test-coverage
test-coverage:
	command -v coverage >/dev/null || { echo "Please install coverage via 'pip install coverage'"; exit 1; }
	cd tests \
	    && coverage run --source=../zeekclient -m unittest \
	       test_brokertypes.py \
	       test_cli.py \
	       test_config_io.py \
	       test_config_overrides.py \
	       test_controller.py \
	       test_types.py \
	    && coverage report -m

.PHONY: dist
dist:
	rm -rf dist/*.tar.gz
	python3 setup.py sdist
	@printf "Package: "; echo dist/*.tar.gz
