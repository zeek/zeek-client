.PHONY: all
all:

.PHONY: test
test:
	cd tests && python -m unittest

.PHONY: test-coverage
test-coverage:
	pytest --cov=zeekclient  --cov-report=html --cov-report=term

.PHONY: man
man:
	./man/build.py

.PHONY: dist
dist:
	rm -rf dist/*.tar.gz
	python3 setup.py sdist
	@printf "Package: "; echo dist/*.tar.gz
