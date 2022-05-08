SRC = secret_sharing.py
TEST = test.py

export PIP_DISABLE_PIP_VERSION_CHECK=1

venv: requirements.txt requirements_dev.txt
	@python3 -m venv $@
	@source $@/bin/activate && pip install -r $< -r requirements_dev.txt
	@echo "enter virtual environment: source $@/bin/activate"

.PHONY: outdated
outdated: venv
	@source $</bin/activate && pip list --$@

tags: $(SRC) $(TEST)
	@ctags --languages=python --python-kinds=-i $(SRC) $(TEST)

.PHONY: test
test:
	@python -m unittest --buffer

coverage: $(SRC) $(TEST)
	@coverage run --branch --concurrency=thread --omit=venv/* test.py
	@coverage report -m
	@coverage html -d ./coverage
	@coverage erase

.PHONY: lint
lint:
	@pylint -f colorized $(SRC) $(TEST)

.PHONY: flake8
flake8:
	@flake8 $(SRC) $(TEST)

.PHONY: typecheck
typecheck:
	@mypy $(SRC) $(TEST)

.PHONY: clean
clean:
	@$(RM) -r coverage/
	@$(RM) -r .mypy_cache/
	@$(RM) -r __pycache__/
	@$(RM) tags
