default: requirements build

build:
	poetry build

publish: build
	poetry publish

requirements:
	poetry export -f requirements.txt --output requirements.txt

update:
	poetry update
