default: download data

download: clean init
	poetry run kev --raw -o data/known_exploited_vulnerabilities.json

init:
	mkdir -p data

clean:
	rm -rf data/*

data: init
	poetry run kev -i o/data/known_exploited_vulnerabilities.json -o data/known_exploited_vulnerabilities_processed.json
	poetry run kev --raw -i o/data/known_exploited_vulnerabilities.json -f jsonl -o data/known_exploited_vulnerabilities.jsonl
	poetry run kev -i o/data/known_exploited_vulnerabilities.json -f json -t cve_ids | jq -r '.[]' > data/cve_ids.txt
	poetry run kev -i o/data/known_exploited_vulnerabilities.json -f json -t due_date -o data/due_dates.json
	poetry run kev -i o/data/known_exploited_vulnerabilities.json -f json -t date_added -o data/dates_added.json
	poetry run kev -i o/data/known_exploited_vulnerabilities.json -f jsonl -o data/known_exploited_vulnerabilities_processed.jsonl
	poetry run kev -i o/data/known_exploited_vulnerabilities.json -f jsonl -t dates -o data/important_dates.jsonl

build:
	poetry build

publish:
	poetry publish

.PHONY: download data
